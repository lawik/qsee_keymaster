defmodule QseeKeymaster.MixProject do
  use Mix.Project

  @version "0.1.0"
  @source_url "https://github.com/lawik/qsee_keymaster"

  def project do
    [
      app: :qsee_keymaster,
      version: @version,
      elixir: "~> 1.18",
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      description:
        "Client for the Keymaster trusted application in Qualcomm's QSEE TrustZone, " <>
          "as left resident by the bootloader on devices like the Fairphone 3.",
      package: package(),
      docs: [main: "readme", extras: ["README.md"]],
      name: "QseeKeymaster",
      source_url: @source_url
    ]
  end

  def application do
    [extra_applications: [:logger]]
  end

  defp deps do
    [
      {:ex_doc, "~> 0.34", only: :dev, runtime: false}
    ]
  end

  defp package do
    [
      licenses: ["Apache-2.0"],
      links: %{"GitHub" => @source_url},
      files: ~w(lib mix.exs README.md)
    ]
  end
end
