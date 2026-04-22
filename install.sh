#!/usr/bin/env sh
set -eu

PREFIX="${PREFIX:-/usr/local}"
BINDIR="${BINDIR:-${PREFIX}/bin}"
APP_DIR="${APP_DIR:-/opt/simple_auth}"
SYSTEMD_DIR="${SYSTEMD_DIR:-/etc/systemd/system}"
SERVICE_NAME="${SERVICE_NAME:-simple_auth.service}"
DESTDIR="${DESTDIR:-}"

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
BIN_SRC="${BIN_SRC:-${SCRIPT_DIR}/simple_auth}"

if [ ! -f "${BIN_SRC}" ]; then
  echo "missing binary: ${BIN_SRC}" >&2
  echo "run this script from an unpacked release package, or place simple_auth next to install.sh" >&2
  exit 1
fi

install_assets() {
  install -d "${DESTDIR}${BINDIR}"
  install -m 0755 "${BIN_SRC}" "${DESTDIR}${BINDIR}/simple_auth"

  install -d "${DESTDIR}${APP_DIR}"
  install -d "${DESTDIR}${APP_DIR}/configs"
  install -m 0644 "${SCRIPT_DIR}/configs/config.yaml" "${DESTDIR}${APP_DIR}/configs/config.yaml.example"
  if [ ! -f "${DESTDIR}${APP_DIR}/configs/config.yaml" ]; then
    install -m 0644 "${SCRIPT_DIR}/configs/config.yaml" "${DESTDIR}${APP_DIR}/configs/config.yaml"
  else
    echo "Keep existing config: ${DESTDIR}${APP_DIR}/configs/config.yaml"
  fi

  rm -rf "${DESTDIR}${APP_DIR}/templates" "${DESTDIR}${APP_DIR}/deploy" "${DESTDIR}${APP_DIR}/doc"
  cp -R "${SCRIPT_DIR}/templates" "${DESTDIR}${APP_DIR}/"
  cp -R "${SCRIPT_DIR}/deploy" "${DESTDIR}${APP_DIR}/"
  cp -R "${SCRIPT_DIR}/doc" "${DESTDIR}${APP_DIR}/"
  install -d "${DESTDIR}${APP_DIR}/logs"
}

install_service() {
  install -d "${DESTDIR}${SYSTEMD_DIR}"
  sed \
    -e "s|@BINDIR@|${BINDIR}|g" \
    -e "s|@APP_DIR@|${APP_DIR}|g" \
    "${SCRIPT_DIR}/deploy/systemd/simple_auth.service.in" > "${DESTDIR}${SYSTEMD_DIR}/${SERVICE_NAME}"
  chmod 0644 "${DESTDIR}${SYSTEMD_DIR}/${SERVICE_NAME}"

  if command -v systemctl >/dev/null 2>&1 && [ -z "${DESTDIR}" ]; then
    systemctl daemon-reload
  else
    echo "Skip systemctl daemon-reload."
  fi
}

service_check() {
  test -x "${DESTDIR}${BINDIR}/simple_auth" || {
    echo "missing executable: ${DESTDIR}${BINDIR}/simple_auth" >&2
    exit 1
  }
  test -f "${DESTDIR}${APP_DIR}/configs/config.yaml" || {
    echo "missing config: ${DESTDIR}${APP_DIR}/configs/config.yaml" >&2
    exit 1
  }
  test -f "${DESTDIR}${APP_DIR}/templates/login.html" || {
    echo "missing template: ${DESTDIR}${APP_DIR}/templates/login.html" >&2
    exit 1
  }
  test -f "${DESTDIR}${SYSTEMD_DIR}/${SERVICE_NAME}" || {
    echo "missing service: ${DESTDIR}${SYSTEMD_DIR}/${SERVICE_NAME}" >&2
    exit 1
  }

  "${DESTDIR}${BINDIR}/simple_auth" -h >/dev/null

  if command -v systemd-analyze >/dev/null 2>&1 && [ -z "${DESTDIR}" ]; then
    systemd-analyze verify "${SYSTEMD_DIR}/${SERVICE_NAME}"
  else
    echo "Skip systemd-analyze verify."
  fi

  if command -v systemctl >/dev/null 2>&1 && [ -z "${DESTDIR}" ]; then
    systemctl cat "${SERVICE_NAME}" >/dev/null
  else
    echo "Skip systemctl unit lookup."
  fi

  echo "Service install check passed."
}

install_assets
install_service
service_check

echo "Installed ${SERVICE_NAME}."
echo "Start it with: systemctl enable --now ${SERVICE_NAME}"
