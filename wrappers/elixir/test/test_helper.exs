ExUnit.start()
ExUnit.configure(exclude: [:skip], trace: true)

# Point ExUnit at the working tree's NIF rather than the Hex-resolved copy
# of :libsignal_protocol_nif that the dependency pulls in. Without this,
# `mix test` in this repo would exercise the last published release instead
# of the code being changed.
#
# add_patha puts the local ebin ahead of the dependency's, and the two stub
# modules are purged first in case the dependency copy is already loaded.
# If there is no working tree (a consumer running these tests from a Hex
# checkout), this is a no-op and the dependency's copy is used.
defmodule LibsignalProtocolTestSetup do
  @local_ebin Path.expand("../../../_build/default/lib/libsignal_protocol_nif/ebin", __DIR__)
  @nif_modules [:libsignal_protocol_nif, :signal_nif]

  def setup do
    if File.dir?(@local_ebin) do
      :code.add_patha(String.to_charlist(@local_ebin))
      Enum.each(@nif_modules, &reload/1)
    end

    Enum.each(@nif_modules, &ensure_loaded!/1)
  end

  defp reload(mod) do
    :code.purge(mod)
    :code.delete(mod)
    :code.purge(mod)
  end

  defp ensure_loaded!(mod) do
    case Code.ensure_loaded(mod) do
      {:module, ^mod} ->
        :ok

      {:error, reason} ->
        raise """
        failed to load #{inspect(mod)}: #{inspect(reason)}.
        Run `make build` in the project root before running wrapper tests.
        """
    end
  end
end

LibsignalProtocolTestSetup.setup()
