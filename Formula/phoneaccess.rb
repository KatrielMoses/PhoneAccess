class Phoneaccess < Formula
  desc "Open-source phone number OSINT tool"
  homepage "https://github.com/KatrielMoses/PhoneAccess"
  version "1.0.0"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/KatrielMoses/PhoneAccess/releases/download/v1.0.0/phoneaccess_darwin_arm64"
      sha256 "945a8e26420c88d3633d275111c5edf3b292ff3e35cf1d997e61ac518cbebf1b"
    end
    on_intel do
      url "https://github.com/KatrielMoses/PhoneAccess/releases/download/v1.0.0/phoneaccess_darwin_amd64"
      sha256 "8f9024e8896ef39f842cbb20a9e1868b13644b700dd080dda22476eff6da7e90"
    end
  end

  def install
    bin.install Dir["phoneaccess_darwin_*"].first => "phoneaccess"
  end

  test do
    system "#{bin}/phoneaccess", "version"
  end
end
