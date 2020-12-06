'use strict';

export function any(promises) {
  if(promises.length < 1) {
    return Promise.resolve(false);
  }
  return Promise.all(
    promises.map($p =>
      $p
        .catch(err => {
          // console.error('Underlying promise rejected', err);
          return false;
        })
        .then(result => {
          if(result) {
            throw new Error('authorized');
          }
        })
    )
  )
    .then(() => false)
    .catch(err => err && err.message === 'authorized');
}

export function isGlob(string) {
  return string.includes('*');
}

export function globToRegex(string) {
  return new RegExp('^' + string.replace(/\*/g, '.*'));
}