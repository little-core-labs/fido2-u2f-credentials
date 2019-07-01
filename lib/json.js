function toJSON(object) {
  const output = {}
  const filter = (k) => undefined !== object[k]
  const reduce = (out, k) => Object.assign(out, { [k]: object[k] })
  return Object.keys(object).filter(filter).reduce(reduce, output)
}

module.exports = {
  toJSON
}
