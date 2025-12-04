defmodule WandererAppWeb.BlogHTML do
  use WandererAppWeb, :html

  embed_templates "blog_html/*"

  @doc """
  Check if WinterCo SEAT authentication is enabled.
  Returns true if WINTERCO_CLIENT_ID and WINTERCO_CLIENT_SECRET are configured.
  """
  def winterco_auth_enabled? do
    config = Application.get_env(:ueberauth, WandererApp.Ueberauth.Strategy.WinterCo.OAuth, [])
    client_id = Keyword.get(config, :client_id, "")
    client_secret = Keyword.get(config, :client_secret, "")

    client_id != "" and client_secret != ""
  end
end
