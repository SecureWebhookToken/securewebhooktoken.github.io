DOCKER_IMAGE := hugomods/hugo:exts
DOCKER_RUN_CMD := docker compose run --rm

all: clean build

up:
	docker compose up server

down:
	docker compose down --remove-orphans

build:
	$(DOCKER_RUN_CMD) server build --minify -d docs

clean:
	rm -rf ./public
	rm -rf ./resources/_gen

shell:
	$(DOCKER_RUN_CMD) server /bin/sh