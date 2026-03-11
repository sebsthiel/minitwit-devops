# MIGRATE DATA FROM SQLITE TO POSTGRESQL USING PGLOADER
The following line should be run from the VPS that has the SQLITE database.
NOTICE: replace the password and droplet ip with actual values
```bash
pgloader sqlite:///data/minitwit.db postgresql://minitwit_user:mypassword123@YOUR_DROPLET_IP/minitwit
```
