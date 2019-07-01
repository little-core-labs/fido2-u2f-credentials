const { Entity } = require('./entity')

const $id = Symbol('id')

class RelyingParty extends Entity {
  constructor(id, name, icon) {
    super(name, icon)
    this[$id] = id
  }

  get id() { return this[$id] }
}

module.exports = {
  RelyingParty
}
