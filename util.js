const isFunction = (f) => 'function' === typeof f
const isBoolean = (b) => 'boolean' === typeof b
const isString = (s) => 'string' === typeof s
const isObject = (o) => o && 'object' === typeof o
const isNumber = (n) => n === n && 'number' === typeof n

const { isBuffer } = Buffer
const { isArray } = Array

module.exports = Object.seal(Object.freeze({
  isFunction,
  isBoolean,
  isString,
  isObject,
  isBuffer,
  isArray,
}))
