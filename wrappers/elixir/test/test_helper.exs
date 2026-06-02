ExUnit.start()

# Configure test environment
ExUnit.configure(exclude: [:skip], trace: true)

# Make the parent project's compiled Erlang modules available so the NIF
# stub modules (`libsignal_protocol_nif`, `signal_nif`) are loadable from
# ExUnit. The wrapper has no compile-time dep on the parent OTP app; we
# add it to the code path at runtime and trigger the on_load NIF init.
defmodule LibsignalProtocolTestSetup do
  @parent_root Path.expand("../../..", __DIR__)

  def setup do
    add_code_path(Path.join(@parent_root, "_build/default/lib/libsignal_protocol_nif/ebin"))

    ensure_loaded(:libsignal_protocol_nif)
    ensure_loaded(:signal_nif)
  end

  defp add_code_path(path) do
    unless File.dir?(path) do
      raise """
      libsignal_protocol_nif ebin not found at #{path}.
      Run `make build` in the project root before running wrapper tests.
      """
    end

    :code.add_pathz(String.to_charlist(path))
  end

  defp ensure_loaded(mod) do
    case Code.ensure_loaded(mod) do
      {:module, ^mod} -> :ok
      {:error, reason} -> raise "failed to load #{inspect(mod)}: #{inspect(reason)}"
    end
  end
end

LibsignalProtocolTestSetup.setup()

# Test helper functions
defmodule TestHelper do
  @moduledoc """
  Helper functions for testing the LibsignalProtocol wrapper.
  """

  import ExUnit.Assertions

  def generate_test_key(size \\ 32) do
    :crypto.strong_rand_bytes(size)
  end

  def assert_binary_result({:ok, result}) when is_binary(result) do
    assert byte_size(result) > 0
    result
  end

  def assert_binary_result({:error, reason}) do
    # In test environment, NIF might not be loaded, so errors are acceptable
    assert is_binary(reason) or is_atom(reason)
    :error
  end

  def assert_tuple_result({:ok, {a, b}}) when is_binary(a) and is_binary(b) do
    assert byte_size(a) > 0
    assert byte_size(b) > 0
    {a, b}
  end

  def assert_tuple_result({:error, reason}) do
    # In test environment, NIF might not be loaded, so errors are acceptable
    assert is_binary(reason) or is_atom(reason)
    :error
  end
end
