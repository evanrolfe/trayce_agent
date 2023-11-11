cd /tmp
curl https://github.com/capstone-engine/capstone/releases/download/5.0-rc2/capstone-5.0-rc2.tar.xz -Lo ./capstone.tar.xz
tar -xf capstone.tar.xz && mv ./capstone-* ./capstone
cd capstone
CAPSTONE_ARCHS="aarch64 x86" ./make.sh
./make.sh install
