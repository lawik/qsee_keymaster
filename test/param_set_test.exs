defmodule QseeKeymaster.ParamSetTest do
  use ExUnit.Case, async: true

  alias QseeKeymaster.{ParamSet, Tag}

  test "tag words follow the AOSP layout" do
    assert Tag.encode(:purpose) == Bitwise.bor(Bitwise.bsl(2, 28), 1)
    assert Tag.encode(:algorithm) == 0x10000002
    assert Tag.encode(:key_size) == 0x30000003
    assert Tag.encode(:rsa_public_exponent) == 0x500000C8
    assert Tag.encode(:application_id) == 0x90000259
    assert Tag.encode(:no_auth_required) == 0x700001F7
    assert Tag.decode(0x10000002) == {:algorithm, :enum}
    assert Tag.decode(0x3000FFFF) == {{:unknown, 0xFFFF}, :uint}
  end

  test "encodes a parameter set the way AuthorizationSet::Serialize does" do
    bin =
      ParamSet.encode([
        {:algorithm, :aes},
        {:key_size, 128},
        {:application_id, "ab"},
        {:no_auth_required, true}
      ])

    assert bin ==
             <<2::little-32, "ab", 4::little-32, 33::little-32, 0x10000002::little-32,
               32::little-32, 0x30000003::little-32, 128::little-32, 0x90000259::little-32,
               2::little-32, 0::little-32, 0x700001F7::little-32, 1>>
  end

  test "round-trips every value type" do
    params = [
      {:purpose, :encrypt},
      {:purpose, :decrypt},
      {:algorithm, :aes},
      {:key_size, 256},
      {:block_mode, :gcm},
      {:padding, :none},
      {:min_mac_length, 128},
      {:rsa_public_exponent, 65537},
      {:user_secure_id, 0x1122334455667788},
      {:active_datetime, 1_700_000_000_000},
      {:caller_nonce, false},
      {:no_auth_required, true},
      {:application_id, "app"},
      {:application_data, <<1, 2, 3, 4>>},
      {:nonce, <<>>}
    ]

    assert {:ok, ^params, ""} = ParamSet.decode(ParamSet.encode(params))
  end

  test "returns trailing bytes and rejects garbage" do
    bin = ParamSet.encode([{:key_size, 1}]) <> "tail"
    assert {:ok, [{:key_size, 1}], "tail"} = ParamSet.decode(bin)
    assert {:error, :malformed} = ParamSet.decode(<<1, 2, 3>>)

    assert {:error, {:bad_indirect_reference, :application_id}} =
             ParamSet.decode(
               <<0::little-32, 1::little-32, 12::little-32, 0x90000259::little-32, 5::little-32,
                 0::little-32>>
             )
  end

  test "empty set" do
    assert ParamSet.encode([]) == <<0::little-32, 0::little-32, 0::little-32>>
    assert {:ok, [], ""} = ParamSet.decode(ParamSet.encode([]))
  end
end
