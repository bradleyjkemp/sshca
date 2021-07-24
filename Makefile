deploy:
	DOCKER_HOST=ssh://root@sshca.bradleyjkemp.dev:2222 docker compose up --build --detach
