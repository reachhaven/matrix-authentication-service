// Copyright 2025, 2026 Element Creations Ltd.
// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2022-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use std::{sync::Arc, time::Duration};

use axum::{
    extract::{Form, Path, State},
    response::{Html, IntoResponse, Response},
};
use axum_extra::TypedHeader;
use hyper::StatusCode;
use mas_axum_utils::{
    GenericError, InternalError,
    cookies::CookieJar,
    csrf::{CsrfExt, ProtectedForm},
};
use mas_data_model::{
    AuthorizationGrant, AuthorizationGrantStage, BoxClock, BoxRng, BrowserSession, Client,
    MatrixUser,
};
use mas_i18n::DataLocale;
use mas_keystore::Keystore;
use mas_matrix::HomeserverConnection;
use mas_policy::Policy;
use mas_router::{PostAuthAction, UrlBuilder};
use mas_storage::{
    BoxRepository,
    oauth2::{OAuth2AuthorizationGrantRepository, OAuth2ClientRepository},
};
use mas_templates::{ConsentContext, PolicyViolationContext, TemplateContext, Templates};
use oauth2_types::requests::{AuthorizationResponse, Prompt};
use thiserror::Error;
use ulid::Ulid;

use super::callback::CallbackDestination;
use crate::{
    BoundActivityTracker, PreferredLanguage, impl_from_error_for_route,
    oauth2::generate_id_token,
    session::{SessionOrFallback, count_user_sessions_for_limiting, load_session_or_fallback},
};

#[derive(Debug, Error)]
pub enum RouteError {
    #[error(transparent)]
    Internal(Box<dyn std::error::Error + Send + Sync>),

    #[error(transparent)]
    Csrf(#[from] mas_axum_utils::csrf::CsrfError),

    #[error("Authorization grant not found")]
    GrantNotFound,

    #[error("Authorization grant {0} already used")]
    GrantNotPending(Ulid),

    #[error("Failed to load client {0}")]
    NoSuchClient(Ulid),
}

impl_from_error_for_route!(mas_templates::TemplateError);
impl_from_error_for_route!(mas_storage::RepositoryError);
impl_from_error_for_route!(mas_policy::LoadError);
impl_from_error_for_route!(mas_policy::EvaluationError);
impl_from_error_for_route!(crate::session::SessionLoadError);
impl_from_error_for_route!(crate::oauth2::IdTokenSignatureError);
impl_from_error_for_route!(super::callback::IntoCallbackDestinationError);
impl_from_error_for_route!(super::callback::CallbackDestinationError);

impl IntoResponse for RouteError {
    fn into_response(self) -> axum::response::Response {
        match self {
            Self::Internal(e) => InternalError::new(e).into_response(),
            e @ Self::NoSuchClient(_) => InternalError::new(Box::new(e)).into_response(),
            e @ Self::GrantNotFound => GenericError::new(StatusCode::NOT_FOUND, e).into_response(),
            e @ Self::GrantNotPending(_) => {
                GenericError::new(StatusCode::CONFLICT, e).into_response()
            }
            e @ Self::Csrf(_) => GenericError::new(StatusCode::BAD_REQUEST, e).into_response(),
        }
    }
}

/// Whether the client asked for the consent screen with `prompt=consent`, as
/// defined in [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest)
fn prompts_for_consent(grant: &AuthorizationGrant) -> bool {
    grant.raw_parameters.get("prompt").is_some_and(|prompt| {
        prompt
            .split(' ')
            .any(|value| matches!(value.parse(), Ok(Prompt::Consent)))
    })
}

/// Fulfill the grant with the browser session, and send the user back to the
/// client
async fn fulfill_grant_and_redirect(
    rng: &mut BoxRng,
    clock: &BoxClock,
    mut repo: BoxRepository,
    key_store: &Keystore,
    url_builder: &UrlBuilder,
    templates: &Templates,
    locale: &DataLocale,
    client: &Client,
    browser_session: &BrowserSession,
    grant: AuthorizationGrant,
) -> Result<Response, RouteError> {
    let callback_destination = CallbackDestination::try_from(&grant)?;

    // The OAuth2 session will be created later at token exchange time.
    let grant = repo
        .oauth2_authorization_grant()
        .fulfill(clock, browser_session, grant)
        .await?;

    let mut params = AuthorizationResponse::default();

    // Did they request an ID token?
    if grant.response_type_id_token {
        // Fetch the last authentication
        let last_authentication = repo
            .browser_session()
            .get_last_authentication(browser_session)
            .await?;

        params.id_token = Some(generate_id_token(
            rng,
            clock,
            url_builder,
            key_store,
            client,
            Some(&grant),
            browser_session,
            None,
            last_authentication.as_ref(),
        )?);
    }

    // Did they request an auth code?
    if let Some(code) = grant.code {
        params.code = Some(code.code);
    }

    repo.save().await?;

    Ok(callback_destination.go(templates, locale, params)?)
}

#[tracing::instrument(
    name = "handlers.oauth2.authorization.consent.get",
    fields(grant.id = %grant_id),
    skip_all,
)]
pub(crate) async fn get(
    mut rng: BoxRng,
    clock: BoxClock,
    PreferredLanguage(locale): PreferredLanguage,
    State(templates): State<Templates>,
    State(url_builder): State<UrlBuilder>,
    State(key_store): State<Keystore>,
    State(homeserver): State<Arc<dyn HomeserverConnection>>,
    mut policy: Policy,
    mut repo: BoxRepository,
    activity_tracker: BoundActivityTracker,
    user_agent: Option<TypedHeader<headers::UserAgent>>,
    cookie_jar: CookieJar,
    Path(grant_id): Path<Ulid>,
) -> Result<Response, RouteError> {
    let (cookie_jar, maybe_session) = match load_session_or_fallback(
        cookie_jar,
        &clock,
        &mut rng,
        &templates,
        &locale,
        Some(PostAuthAction::continue_grant(grant_id)),
        &mut repo,
    )
    .await?
    {
        SessionOrFallback::MaybeSession {
            cookie_jar,
            maybe_session,
            ..
        } => (cookie_jar, maybe_session),
        SessionOrFallback::Fallback { response } => return Ok(response),
    };

    let user_agent = user_agent.map(|ua| ua.to_string());

    let grant = repo
        .oauth2_authorization_grant()
        .lookup(grant_id)
        .await?
        .ok_or(RouteError::GrantNotFound)?;

    let client = repo
        .oauth2_client()
        .lookup(grant.client_id)
        .await?
        .ok_or(RouteError::NoSuchClient(grant.client_id))?;

    if !matches!(grant.stage, AuthorizationGrantStage::Pending) {
        return Err(RouteError::GrantNotPending(grant.id));
    }

    let Some(session) = maybe_session else {
        let login = mas_router::Login::and_continue_grant(grant_id);
        return Ok((cookie_jar, url_builder.redirect(&login)).into_response());
    };

    activity_tracker
        .record_browser_session(&clock, &session)
        .await;

    let (csrf_token, cookie_jar) = cookie_jar.csrf_token(&clock, &mut rng);

    let session_counts = count_user_sessions_for_limiting(&mut repo, &session.user).await?;

    let res = policy
        .evaluate_authorization_grant(mas_policy::AuthorizationGrantInput {
            user: Some(&session.user),
            client: &client,
            session_counts: Some(session_counts),
            scope: &grant.scope,
            grant_type: mas_policy::GrantType::AuthorizationCode,
            requester: mas_policy::Requester {
                ip_address: activity_tracker.ip(),
                user_agent,
            },
        })
        .await?;

    if res.valid() && client.skip_consent && !prompts_for_consent(&grant) {
        let response = fulfill_grant_and_redirect(
            &mut rng,
            &clock,
            repo,
            &key_store,
            &url_builder,
            &templates,
            &locale,
            &client,
            &session,
            grant,
        )
        .await?;

        return Ok((cookie_jar, response).into_response());
    }

    // We can close the repository early, we don't need it at this point
    repo.save().await?;

    if !res.valid() {
        let ctx = PolicyViolationContext::for_authorization_grant(grant, client, res.violations)
            .with_session(session)
            .with_csrf(csrf_token.form_value())
            .with_language(locale);

        let content = templates.render_policy_violation(&ctx)?;

        return Ok((cookie_jar, Html(content)).into_response());
    }

    // Fetch informations about the user. This is purely cosmetic, so we let it
    // fail and put a 1s timeout to it in case we fail to query it
    // XXX: we're likely to need this in other places
    let localpart = &session.user.username;
    let display_name = match tokio::time::timeout(
        Duration::from_secs(1),
        homeserver.query_user(localpart),
    )
    .await
    {
        Ok(Ok(user)) => user.displayname,
        Ok(Err(err)) => {
            tracing::warn!(
                error = &*err as &dyn std::error::Error,
                localpart,
                "Failed to query user"
            );
            None
        }
        Err(_) => {
            tracing::warn!(localpart, "Timed out while querying user");
            None
        }
    };

    let matrix_user = MatrixUser {
        mxid: homeserver.mxid(localpart),
        display_name,
    };

    let ctx = ConsentContext::new(grant, client, matrix_user)
        .with_session(session)
        .with_csrf(csrf_token.form_value())
        .with_language(locale);

    let content = templates.render_consent(&ctx)?;

    Ok((cookie_jar, Html(content)).into_response())
}

#[tracing::instrument(
    name = "handlers.oauth2.authorization.consent.post",
    fields(grant.id = %grant_id),
    skip_all,
)]
pub(crate) async fn post(
    mut rng: BoxRng,
    clock: BoxClock,
    PreferredLanguage(locale): PreferredLanguage,
    State(templates): State<Templates>,
    State(key_store): State<Keystore>,
    mut policy: Policy,
    mut repo: BoxRepository,
    activity_tracker: BoundActivityTracker,
    user_agent: Option<TypedHeader<headers::UserAgent>>,
    cookie_jar: CookieJar,
    State(url_builder): State<UrlBuilder>,
    Path(grant_id): Path<Ulid>,
    Form(form): Form<ProtectedForm<()>>,
) -> Result<Response, RouteError> {
    cookie_jar.verify_form(&clock, form)?;

    let (cookie_jar, maybe_session) = match load_session_or_fallback(
        cookie_jar,
        &clock,
        &mut rng,
        &templates,
        &locale,
        Some(PostAuthAction::continue_grant(grant_id)),
        &mut repo,
    )
    .await?
    {
        SessionOrFallback::MaybeSession {
            cookie_jar,
            maybe_session,
            ..
        } => (cookie_jar, maybe_session),
        SessionOrFallback::Fallback { response } => return Ok(response),
    };

    let (csrf_token, cookie_jar) = cookie_jar.csrf_token(&clock, &mut rng);

    let user_agent = user_agent.map(|ua| ua.to_string());

    let grant = repo
        .oauth2_authorization_grant()
        .lookup(grant_id)
        .await?
        .ok_or(RouteError::GrantNotFound)?;

    let Some(browser_session) = maybe_session else {
        let next = PostAuthAction::continue_grant(grant_id);
        let login = mas_router::Login::and_then(next);
        return Ok((cookie_jar, url_builder.redirect(&login)).into_response());
    };

    activity_tracker
        .record_browser_session(&clock, &browser_session)
        .await;

    let client = repo
        .oauth2_client()
        .lookup(grant.client_id)
        .await?
        .ok_or(RouteError::NoSuchClient(grant.client_id))?;

    if !matches!(grant.stage, AuthorizationGrantStage::Pending) {
        return Err(RouteError::GrantNotPending(grant.id));
    }

    let session_counts = count_user_sessions_for_limiting(&mut repo, &browser_session.user).await?;

    let res = policy
        .evaluate_authorization_grant(mas_policy::AuthorizationGrantInput {
            user: Some(&browser_session.user),
            client: &client,
            session_counts: Some(session_counts),
            scope: &grant.scope,
            grant_type: mas_policy::GrantType::AuthorizationCode,
            requester: mas_policy::Requester {
                ip_address: activity_tracker.ip(),
                user_agent,
            },
        })
        .await?;

    if !res.valid() {
        let ctx = PolicyViolationContext::for_authorization_grant(grant, client, res.violations)
            .with_session(browser_session)
            .with_csrf(csrf_token.form_value())
            .with_language(locale);

        let content = templates.render_policy_violation(&ctx)?;

        return Ok((cookie_jar, Html(content)).into_response());
    }

    // All good, let's fulfill the grant with the browser session.
    let response = fulfill_grant_and_redirect(
        &mut rng,
        &clock,
        repo,
        &key_store,
        &url_builder,
        &templates,
        &locale,
        &client,
        &browser_session,
        grant,
    )
    .await?;

    Ok((cookie_jar, response).into_response())
}

#[cfg(test)]
mod tests {
    use hyper::{
        Request, Response, StatusCode,
        header::{CONTENT_TYPE, LOCATION},
    };
    use mas_axum_utils::SessionInfoExt;
    use mas_data_model::{AuthorizationGrant, AuthorizationGrantStage, Clock, UlidExt as _};
    use mas_iana::oauth::OAuthClientAuthenticationMethod;
    use mas_storage::RepositoryAccess;
    use sqlx::PgPool;
    use ulid::Ulid;

    use crate::test_utils::{CookieHelper, RequestBuilderExt, ResponseExt, TestState, setup};

    /// Sign a user in, configure a static client and send an authorization
    /// request for it, returning the session cookies and the grant ID
    async fn start_grant(
        state: &TestState,
        skip_consent: bool,
        prompt: Option<&str>,
    ) -> (CookieHelper, Ulid) {
        let mut rng = state.rng();
        let mut repo = state.repository().await.unwrap();

        let user = repo
            .user()
            .add(&mut rng, &state.clock, "alice".to_owned())
            .await
            .unwrap();
        let browser_session = repo
            .browser_session()
            .add(&mut rng, &state.clock, &user, None)
            .await
            .unwrap();

        let client_id = Ulid::from_datetime_with_rng(state.clock.now(), &mut rng);
        repo.oauth2_client()
            .upsert_static(
                client_id,
                Some("Static client".to_owned()),
                None,
                OAuthClientAuthenticationMethod::None,
                None,
                None,
                None,
                vec!["https://example.com/callback".parse().unwrap()],
                skip_consent,
            )
            .await
            .unwrap();

        repo.save().await.unwrap();

        let cookies = CookieHelper::new();
        cookies.import(state.cookie_jar().set_session(&browser_session));

        let query = {
            let mut query = url::form_urlencoded::Serializer::new(String::new());
            query
                .append_pair("response_type", "code")
                .append_pair("client_id", &client_id.to_string())
                .append_pair("redirect_uri", "https://example.com/callback")
                .append_pair("scope", "openid")
                .append_pair("state", "test-state-value");
            if let Some(prompt) = prompt {
                query.append_pair("prompt", prompt);
            }
            query.finish()
        };

        let request = cookies.with_cookies(Request::get(format!("/authorize?{query}")).empty());
        let response = state.request(request).await;
        response.assert_status(StatusCode::SEE_OTHER);

        let grant_id = response.headers()[LOCATION]
            .to_str()
            .unwrap()
            .strip_prefix("/consent/")
            .expect("the authorization request should continue to the consent screen")
            .parse()
            .unwrap();

        (cookies, grant_id)
    }

    async fn get_consent(
        state: &TestState,
        cookies: &CookieHelper,
        grant_id: Ulid,
    ) -> Response<String> {
        let request = cookies.with_cookies(Request::get(format!("/consent/{grant_id}")).empty());
        state.request(request).await
    }

    async fn lookup_grant(state: &TestState, grant_id: Ulid) -> AuthorizationGrant {
        let mut repo = state.repository().await.unwrap();
        repo.oauth2_authorization_grant()
            .lookup(grant_id)
            .await
            .unwrap()
            .unwrap()
    }

    fn assert_consent_screen(response: &Response<String>) {
        response.assert_status(StatusCode::OK);
        response.assert_header_value(CONTENT_TYPE, "text/html; charset=utf-8");
        assert!(response.body().contains("layout-container consent"));
    }

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_skip_consent(pool: PgPool) {
        setup();
        let state = TestState::from_pool(pool).await.unwrap();
        let (cookies, grant_id) = start_grant(&state, true, None).await;

        let response = get_consent(&state, &cookies, grant_id).await;
        response.assert_status(StatusCode::SEE_OTHER);

        let grant = lookup_grant(&state, grant_id).await;
        assert!(matches!(
            grant.stage,
            AuthorizationGrantStage::Fulfilled { .. }
        ));
        let code = grant.code.unwrap().code;
        response.assert_header_value(
            LOCATION,
            &format!("https://example.com/callback?state=test-state-value&code={code}#"),
        );
    }

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_consent_screen_without_skip_consent(pool: PgPool) {
        setup();
        let state = TestState::from_pool(pool).await.unwrap();
        let (cookies, grant_id) = start_grant(&state, false, None).await;

        let response = get_consent(&state, &cookies, grant_id).await;
        assert_consent_screen(&response);

        let grant = lookup_grant(&state, grant_id).await;
        assert!(matches!(grant.stage, AuthorizationGrantStage::Pending));
    }

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_consent_screen_with_prompt_consent(pool: PgPool) {
        setup();
        let state = TestState::from_pool(pool).await.unwrap();
        let (cookies, grant_id) = start_grant(&state, true, Some("consent")).await;

        let response = get_consent(&state, &cookies, grant_id).await;
        assert_consent_screen(&response);

        let grant = lookup_grant(&state, grant_id).await;
        assert!(matches!(grant.stage, AuthorizationGrantStage::Pending));
    }
}
