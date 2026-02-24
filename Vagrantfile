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
    apt-get install -y golang git build-essential ufw

    git clone https://github.com/sebsthiel/minitwit-devops.git /home/vagrant/app
    cd /home/vagrant/app

    go mod tidy
    go build -o minitwit

    ufw allow 5000

    nohup ./minitwit > output.log 2>&1 &
  SHELL
end