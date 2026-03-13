Vagrant.configure("2") do |config|
  # Dummy box for DO provider
  config.vm.box = "dummy"

  # Disable synced folders
  config.vm.synced_folder ".", "/vagrant", disabled: true

  do_token   = ENV.fetch("DIGITAL_OCEAN_TOKEN")
  ssh_key    = ENV.fetch("DIGITAL_OCEAN_SSH_KEY_PATH", "~/.ssh/do_vagrant")
  ssh_key    = File.expand_path(ssh_key)
  ssh_key_nm = ENV.fetch("DIGITAL_OCEAN_SSH_KEY_NAME", "do-vagrant")

      # --- APP SERVER ---
  config.vm.define "app" do |app|
    # DigitalOcean provider
    app.vm.provider :digital_ocean do |provider, override|
      provider.token = do_token
      provider.image = "ubuntu-22-04-x64"
      provider.region = "fra1"
      provider.size = "s-1vcpu-1gb"
      provider.ssh_key_name = ssh_key_nm 
      provider.name = "minitwit-dev"
      
      # SSH key path
      override.ssh.private_key_path = ssh_key
    end

    # Provision
    app.vm.provision "shell", inline: <<-SHELL
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
  # --- DB SERVER ---
  config.vm.define "db" do |db|
    db.vm.provider :digital_ocean do |provider, override|
      provider.token = do_token
      provider.image = "ubuntu-22-04-x64"
      provider.region = "fra1"
      provider.size = "s-1vcpu-1gb"
      provider.ssh_key_name = ssh_key_nm
      provider.name = "minitwit-db"

      override.ssh.private_key_path = ssh_key
    end

    db_password = ENV.fetch("MINITWIT_DB_PASS", "minitwitpassword123")
    db.vm.provision "shell", inline: <<-SHELL
      set -e
      apt-get update -y
      apt-get install -y postgresql postgresql-contrib git

      # repo needed to get the schema.sql file
      if [ ! -d /home/vagrant/app/.git ]; then
        git clone https://github.com/sebsthiel/minitwit-devops.git /home/vagrant/app
      fi

      # Allow remote connections
      echo "listen_addresses = '*'" >> /etc/postgresql/*/main/postgresql.conf
      echo "host all all 0.0.0.0/0 md5" >> /etc/postgresql/*/main/pg_hba.conf

      systemctl enable postgresql
      systemctl start postgresql


      export DBPASSWORD="#{db_password}"

      # create db + user
      sudo -u postgres psql <<EOF
      CREATE USER minitwit_user WITH PASSWORD '${DBPASSWORD}';
      CREATE DATABASE minitwit OWNER minitwit_user;
      EOF
      
    SHELL
  end
end