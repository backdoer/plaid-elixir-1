defmodule Plaid.Identity do
  @moduledoc """
  Functions for Plaid `identity` endpoint.
  """

  import Plaid, only: [make_request_with_cred: 4, validate_cred: 1]

  alias Plaid.Utils

  @derive Jason.Encoder
  defstruct accounts: [], item: nil, request_id: nil

  @type t :: %__MODULE__{
          accounts: [Plaid.Accounts.Account.t()],
          item: Plaid.Item.t(),
          request_id: String.t()
        }
  @type params :: %{
          required(:access_token) => String.t()
        }
  @type config :: %{required(atom) => String.t()}

  @endpoint :identity

  @doc """
  Gets identity data associated with an Item.

  Parameters
  ```
  %{
    access_token: "access-env-identifier"
  }
  ```
  """
  @spec get(params, config | nil) :: {:ok, Plaid.Identity.t()} | {:error, Plaid.Error.t()}
  def get(params, config \\ %{}) do
    config = validate_cred(config)
    endpoint = "#{@endpoint}/get"

    :post
    |> make_request_with_cred(endpoint, config, params)
    |> Utils.handle_resp(@endpoint)
  end
end
