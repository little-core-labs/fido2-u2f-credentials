const { Entity } = require('./entity')

const $id = Symbol('id')
const $displayName = Symbol('displayName')

class User extends Entity {
  constructor(id, name, icon) {
    super(name, icon)
    this[$id] = id
  }

  get id() { return this[$id] }
}

module.exports = {
  User
}
