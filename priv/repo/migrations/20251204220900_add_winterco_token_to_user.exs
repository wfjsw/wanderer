defmodule WandererApp.Repo.Migrations.AddWintercoTokenToUser do
  @moduledoc """
  Adds WinterCo SEAT OAuth token columns to the user table.

  These columns store the WinterCo access_token and refresh_token which are used
  to obtain EVE Online tokens via the passthrough endpoint, similar to how
  EVE Online tokens are stored on the character table.
  """
  use Ecto.Migration

  def change do
    alter table(:user_v1) do
      add :winterco_access_token, :binary
      add :winterco_refresh_token, :binary
      add :winterco_expires_at, :bigint
    end
  end
end
