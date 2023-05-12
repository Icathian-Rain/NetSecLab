#!/bin/bash

cp -rf ./src/cert ./docker/clientVolumes/
cp -rf ./src/cert ./docker/serverVolumes/

cp -f ./src/miniVPN/build/miniVPN ./docker/clientVolumes/miniVPN
cp -f ./src/miniVPN/build/miniVPN ./docker/serverVolumes/miniVPN

