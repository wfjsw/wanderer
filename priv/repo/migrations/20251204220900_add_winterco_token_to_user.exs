defmodule WandererApp.Repo.Migrations.AddWintercoTokenToUser do
  @moduledoc """
  Adds WinterCo SEAT OAuth token columns to the user table.

  These columns store the WinterCo access_token and refresh_token which are used
  to obtain EVE Online tokens via the passthrough endpoint, similar to how
  EVE Online tokens are stored on the character table.

  Note: Cloaked (encrypted) fields use the encrypted_ prefix in the database.
  """
  use Ecto.Migration

  def change do
    alter table(:user_v1) do
      # Encrypted fields (using AshCloak) need the encrypted_ prefix in the database
      add :encrypted_winterco_access_token, :binary
      add :encrypted_winterco_refresh_token, :binary
      # Non-encrypted field
      add :winterco_expires_at, :bigint
    end
  end
end
