defmodule Plaid.Webhook do
  @moduledoc """
  Creates a plaid Event from webhook's payload if signature is valid.
  """

  import Plaid, only: [make_request_with_cred: 4, validate_cred: 1]
  alias Plaid.Utils
  alias Plaid.Webhooks.AuthWebhook

  @enpoint :webhook_verification_key

  @spec construct_webhook_event(Plaid.Event.t(), String.t(), String.t(), integer) ::
          {:ok, map()} | {:error, any}
        when params: %{
               :body => String.t(),
               :client_id => String.t(),
               :jwt_string => String.t(),
               :secret => String.t()
             }
  def construct_webhook_event(params, config \\ %{}) do
    with {:ok, %{"alg" => "ES256", "kid" => kid}} <- Joken.peek_header(params.jwt_string),
         response =
           retreive_public_key(
             %{client_id: params.client_id, secret: params.secret, key_id: kid},
             config
           ) do
      :ok ->
        {:ok, convert_to_event!(payload)}

      error ->
        error
    end
  end

  @spec retreive_public_key(params, config | nil) :: {:ok, map} | {:error, Plaid.Error.t()}
  defp retreive_public_key(params, config \\ %{}) do
    config = validate_cred(config)
    endpoint = "#{@endpoint}/get"

    make_request_with_cred(:post, endpoint, config, params)
    |> Utils.handle_resp(@endpoint)
    |> IO.inspect()
  end
end
