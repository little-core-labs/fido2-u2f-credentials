const $name = Symbol('name')
const $icon = Symbol('icon')

class Entity {
  constructor(name, icon) {
    this[$name] = name
    this[$icon] = icon
  }

  get name() { return this[$name] }
  get icon() { return this[$icon] }
}

module.exports = {
  Entity,
}
