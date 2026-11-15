.PHONY: all up dev build clean

all: clean build

up: dev

dev:
	npm run dev

build:
	rm -rf ./docs
	npm run build

clean:
	rm -rf ./dist ./.astro ./docs
