Vagrant.configure("2") do |config|
  # Dummy box for DO provider
  config.vm.box = "dummy"

  # Disable synced folders
  config.vm.synced_folder ".", "/vagrant", disabled: true

  # DigitalOcean provider
  config.vm.provider :digital_ocean do |provider|
    provider.token = ENV['DIGITAL_OCEAN_TOKEN']   # <-- variable name
    provider.image = "ubuntu-22-04-x64"
    provider.region = "fra1"
    provider.size = "s-1vcpu-1gb"
    provider.ssh_key_name = ENV['asgerkey']   # <-- variable name
  end

  # SSH key path
  config.ssh.private_key_path = "C:/Users/asger/.ssh/id_rsa"

  # Provision
  config.vm.provision "shell", inline: <<-SHELL
    apt-get update -y
    apt-get install -y haveged
    systemctl enable haveged
    systemctl start haveged
    apt-get install -y git build-essential ufw

    # Install Go 1.25.6 (system-wide) per official guidance
    sudo rm -rf /usr/local/go
    wget -q https://go.dev/dl/go1.25.6.linux-amd64.tar.gz
    sudo tar -C /usr/local -xzf go1.25.6.linux-amd64.tar.gz

    echo 'export PATH=$PATH:/usr/local/go/bin' | sudo tee /etc/profile.d/go.sh >/dev/null
    export PATH=$PATH:/usr/local/go/bin

    go version

    git clone https://github.com/sebsthiel/minitwit-devops.git /home/vagrant/app
    cd /home/vagrant/app

    go mod tidy
    go build -o /usr/local/bin/minitwit .


    ufw allow 5000

    # Start in background
    nohup /usr/local/bin/minitwit > /home/vagrant/output.log 2>&1 &
  SHELL
end