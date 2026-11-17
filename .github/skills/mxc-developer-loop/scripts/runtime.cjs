'use strict';

function validateCaptureProbe(probe, evidence) {
  const reject = message => { throw new Error(`${message}; see ${evidence}`); };
  if (!probe || typeof probe.tier !== 'string' || !probe.probes) {
    reject('Selected runtime returned an unsupported probe format');
  }
  const { nativeCaptureAvailable, guardedCaptureAvailable } = probe.probes;
  if (typeof nativeCaptureAvailable !== 'boolean' && typeof guardedCaptureAvailable !== 'boolean') {
    reject('Selected runtime probe lacks boolean capture capability fields; choose a compatible runtime before starting a fresh results directory');
  }
  if (nativeCaptureAvailable !== true && guardedCaptureAvailable !== true) {
    reject('Selected runtime does not confirm supported denial capture');
  }
  if (probe.needsDaclAugmentation !== false) {
    throw new Error('Host probe requires unsupported DACL augmentation');
  }
}

module.exports = { validateCaptureProbe };
