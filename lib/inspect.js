function inspect(holder, object) {
  try {
    return Object.assign(holder, object.toJSON())
  } catch (err) {
    return Object.assign(holder, object)
  }
}

module.exports = {
  inspect
}
