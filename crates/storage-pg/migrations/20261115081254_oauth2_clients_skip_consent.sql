-- Copyright 2026 Element Creations Ltd.
--
-- SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
-- Please see LICENSE files in the repository root for full details.

-- Lets statically configured clients skip the consent screen
ALTER TABLE "oauth2_clients"
    ADD COLUMN "skip_consent" BOOLEAN NOT NULL DEFAULT FALSE;
