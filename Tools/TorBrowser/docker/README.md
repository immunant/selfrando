# Docker build setup for tor-browser-bundle

This is a Docker-based build setup that allows any user to build
tor-browser-bundle on any Linux distro. This setup builds a Ubuntu 14.04.5
Docker image that contains all needed prerequisites that would be required by
`check-prerequisites.sh`.

The steps to take to build tor-browser-bundle using this setup are:
 * Outside any docker instance, check out the `tor-browser-bundle` and the corresponding `gitian-builder`
repositories somewhere on the local filesystem (we will refer to this location as
`$TORBUILD`).

 * Build the Docker image using `sh ./build_image.sh --build-arg password=<password> <other docker arguments...>`.
   The image will be built for the required user, but require its own password
   to be used when running `sudo` inside the Docker instance.
   Other Docker build arguments may be specified on the command line

 * Run a Docker container based on the build image:
   `sh ./run_docker.sh -v $TORBUILD:<path in docker image> <other docker arguments...>`
   This command will map `$TORBUILD` to a volume inside the container.

 * Inside the container, switch to the directory containing the
   tor-browser-bundle files and run `make nightly` or any other build commands.

The `-v $TORBUILD:<path in docker image>` arguments above map the `$TORBUILD`
path on the host to a path inside the container. 

The `./build-image.sh` script accepts a variety of build arguments which can be
added using `--build-arg`:
 * `user` specifies the name of the user to create inside the Docker
   image, that the build process will run as. Defaults to the name of the user
   that runs `build-image.sh`.

 * `password` specifies the password for the user. This is mainly
   required to run `sudo` in `make-vms.sh`.

 * `useruid` and `usergid` specify the UID and GID for the user.
   `useruid` defaults to the UID of the user running `build-image.sh`, while
   `usergid` defaults to 1000.

 * `kvmgid` is the GID of the `/dev/kvm` device file. This is automatically set
   by `build-image.sh`, so should not be set manually in most cases.

 * `jobs` specifies the number of Make jobs to run, and the number of CPU cores
   to assign to QEMU instances. Sets `NUM_PROCS` for the tor-browser-bundle
   build. 
 
 * `memory` specifies how much memory to give to QEMU instances. Defaults to
   8GB.

### Warnings
 * Building the Docker image requires a password. This password should not be
   considered secure, and can be easily revealed by calling `docker history` on
the built image. We recommend that the built docker image (called `tbb-build`)
is deleted as soon as possible after the build completes using `docker rmi
tbb-build`.

 * The Docker container runs in privileged mode, with full access to the
   system (this is required to run QEMU and `make-vms.sh`).
   Running `run_docker.sh` may require that the current user is added to
   the `docker` group either permanently or temporarily (the preferred approach)
   using `newgrp docker`.
