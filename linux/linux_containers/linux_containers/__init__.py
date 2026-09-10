"""linux_containers - reconstruct container activity from on-disk state.

Reads the container-runtime data directories under a mounted image or a
live root and produces one normalised record per container:

* **Docker** - ``/var/lib/docker/containers/<id>/config.v2.json`` +
  ``hostconfig.json`` + the ``<id>-json.log`` console log; image names
  from ``image/*/repositories.json``.
* **Podman** - ``/var/lib/containers/storage/overlay-containers/
  containers.json`` + per-container ``userdata/config.json`` (OCI runtime
  spec); image names from ``overlay-images/images.json``.
* **containerd** - the OCI ``config.json`` under
  ``io.containerd.runtime.v2.task/<ns>/<id>/``.

Per container: engine, id, name, image, created / started / finished,
exit code, entrypoint + command, environment, bind mounts, published
ports, and the security posture (privileged, added capabilities, host
namespaces, ``SecurityOpt``, run-as user).

Flags privileged containers, a mounted Docker socket, host-path /
sensitive bind mounts, host PID / network / IPC namespaces, dangerous
added capabilities, disabled seccomp / AppArmor, secret-looking
environment variables and cradle-style entrypoints.  Pure standard
library.
"""

__version__ = "0.1.0"
