defmodule QseeKeymasterTest do
  use ExUnit.Case, async: true

  alias QseeKeymaster.Command

  test "command ids match LK's km_main.h" do
    assert Command.id(:generate_key) == 0x108
    assert Command.id(:begin) == 0x10F
    assert Command.id(:finish) == 0x112
    assert Command.id(:get_version) == 0x200
    assert Command.id(:get_date_support) == 0x215
    assert Command.name(0x204) == :milestone_call
    assert Command.name(0x2FF) == 0x2FF
  end

  test "version parses the response the phone gives, through a fake transport" do
    fake = fn <<0x200::little-32>>, 64 ->
      {:ok,
       <<0::little-signed-32, 4::little-32, 0::little-32, 4::little-32, 164::little-32,
         0::size(352)>>}
    end

    assert {:ok, %{major: 4, minor: 0, ta_major: 4, ta_minor: 164}} =
             QseeKeymaster.version(transport: fake)
  end

  test "a non-zero keymaster status is an error" do
    fake = fn _req, _len -> {:ok, <<-38::little-signed-32, 0::size(480)>>} end
    assert {:error, {:keymaster, -38}} = QseeKeymaster.version(transport: fake)
    assert {:error, {:keymaster, -38}} = QseeKeymaster.date_support(transport: fake)
  end

  test "request prefixes the command id" do
    assert QseeKeymaster.request(:abort, <<7::little-64>>) == <<0x113::little-32, 7::little-64>>
  end
end
