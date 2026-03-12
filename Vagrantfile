Vagrant.configure("2") do |config|
  config.vm.define "minitwit-cicd-test-droplet-2" do |vm|
    # Dummy box for DO provider
    vm.vm.box = "minitwit-cicd-test-box"

    # Disable synced folders
    vm.vm.synced_folder ".", "/vagrant", disabled: true

    do_token   = ENV.fetch("DIGITAL_OCEAN_TOKEN")
    ssh_key    = ENV.fetch("DIGITAL_OCEAN_SSH_KEY_PATH", "~/.ssh/do_vagrant_cicd_test_ssh_key")
    ssh_key    = File.expand_path(ssh_key)
    ssh_key_nm = ENV.fetch("DIGITAL_OCEAN_SSH_KEY_NAME", "do_vagrant_cicd_test_ssh_key")

    # DigitalOcean provider
    vm.vm.provider :digital_ocean do |provider, override|
      provider.token = do_token
      provider.image = "ubuntu-22-04-x64"
      provider.region = "fra1"
      provider.size = "s-1vcpu-1gb"
      provider.ssh_key_name = ssh_key_nm
      provider.name = "minitwit-cicd-test-droplet-2"
      override.vm.hostname = "minitwit-cicd-test-droplet-2"

      # SSH key path
      override.ssh.private_key_path = ssh_key
    end

    # Provision
    vm.vm.provision "shell", inline: <<-SHELL
    set -e # Will stop and exit if something fails

    apt-get update -y
    apt-get install -y haveged git ca-certificates curl gnupg lsb-release
    systemctl enable --now haveged

    # Docker repo + key
    install -m 0755 -d /etc/apt/keyrings
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
    chmod a+r /etc/apt/keyrings/docker.gpg

    echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" \
      > /etc/apt/sources.list.d/docker.list

    apt-get update -y

    # Docker Engine + Compose plugin
    apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

    # Clone/update app
    if [ ! -d /home/vagrant/app/.git ]; then
      git clone https://github.com/sebsthiel/minitwit-devops.git /home/vagrant/app
    else
      cd /home/vagrant/app
      git pull
    fi

    cd /home/vagrant/app

    # Build/run
    sudo docker build -f Dockerfile -t minitwit-app .
    sudo docker compose up -d --build

    sudo docker compose ps
    SHELL
  end
end