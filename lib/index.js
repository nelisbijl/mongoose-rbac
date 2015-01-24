var mongoose = require('mongoose')
  , Query = mongoose.Query
  , diff = require('rus-diff').diff
  , extend = require('node.extend')
  , async = require('async')
  , CAN_ALL = 'all'
  , CAN_ANY = 'any'
  , PermissionSchema
  , Permission
  , RoleSchema
  , Role;

require('mongoose-function')(mongoose);

var DecoratedPermissionSchema = mongoose.Schema({
  permission: { type: mongoose.Schema.Types.ObjectId, ref: 'Permission' },
  settings: mongoose.Schema.Types.Mixed,
  settingsFactory: Function
}, {
  _id: false,
  id: false
});

PermissionSchema = mongoose.Schema({
  name: { type: String, required: true },
  displayName: String,
  description: String
});

PermissionSchema.statics.findOrCreate = function (params, callback) {
  var that = this;

  function findOrCreateOne(params, callback) {
    that.findOne(params, function (err, permission) {
      if (err) return callback(err);
      if (permission) return callback(null, permission);
      that.create(params, callback);
    });
  }

  if (Array.isArray(params)) {
    var permissions = [];
    async.forEachSeries(params, function (param, next) {
      findOrCreateOne(param, function (err, permission) {
        permissions.push(permission);
        next(err);
      });
    }, function (err) {
      callback.apply(null, [err].concat(permissions));
    });
  }
  else {
    findOrCreateOne(params, callback);
  }
};

var DecoratedRoleSchema = mongoose.Schema({
  role: { type: mongoose.Schema.Types.ObjectId, ref: 'Role' },
  settings: mongoose.Schema.Types.Mixed,
  settingsFactory: Function
}, {
  _id: false,
  id: false
});

RoleSchema = mongoose.Schema({
  name: { type: String, required: true },
  displayName: String,
  description: String,
  roles: [DecoratedRoleSchema],
  permissions: [DecoratedPermissionSchema]
});

RoleSchema.methods.hasRole = hasRole;

RoleSchema.methods.canAddRole = canAddRole;

// TODO: add grantor + datetime
RoleSchema.methods.addRole = addRole;

// TODO: keep history
RoleSchema.methods.removeRole = removeRole;

RoleSchema.methods.addPermission = addPermission;

RoleSchema.methods.removePermission = removePermission;

DecoratedRoleSchema.methods.can = function (permissionName, done) {
  var decoratedRole = this;
  mongoose.model('Role').findById(decoratedRole.role._id, function (err, role) {
    if (err) return done(err);
    doCan.call(role, decoratedRole.settings, CAN_ALL, [permissionName], true, done);
  });
};

DecoratedRoleSchema.methods.canAll = function (permissionNames, done) {
  var decoratedRole = this;
  mongoose.model('Role').findById(decoratedRole.role._id, function (err, role) {
    if (err) return done(err);
    doCan.call(role, decoratedRole.settings, CAN_ALL, permissionNames, true, done);
  });
};

DecoratedRoleSchema.methods.canAny = function (permissionNames, needPermissions, done) {
  var decoratedRole = this;
  if ('function' === typeof needPermissions) {
    done = needPermissions;
    needPermissions = false;
  }

  mongoose.model('Role').findById(decoratedRole.role._id, function (err, role) {
    if (err) return done(err);
    doCan.call(role, decoratedRole.settings, CAN_ANY, permissionNames, needPermissions, done);
  });
};

RoleSchema.pre('save', function (done) {
  var that = this;
  mongoose.model('Role').findOne({ name: that.name }, function (err, role) {
    if (err) {
      done(err);
    }
    else if (role && !(role._id.equals(that._id))) {
      that.invalidate('name', 'name must be unique');
      done(new Error('Role name must be unique'));
    }
    else {
      done();
    }
  });
});

function testRecursion(targetRole, role, done) {
  role.populate('roles.role', function (err, obj) {
    if (err) return done(err);
    if (obj.roles) {
      var hasRecursion = false, iter = 0;
      async.until(
        function () {
          return hasRecursion || iter === obj.roles.length;
        },
        function (next) {
          var childRole = obj.roles[iter].role;
          hasRecursion = childRole._id.equals(targetRole._id);
          iter++;
          if (hasRecursion) return next();
          testRecursion(targetRole, childRole, function (err, recursion) {
            if (err) return next(err);
            hasRecursion = recursion;
            next();
          });
        },
        function (err) {
          done(err, hasRecursion);
        });
    } else {
      return done(null, false);
    }
  });
}

function doCan(roleSettings, type, permissionNames, needPermissions, done) {
  var role = this,
    foundPermissions = {}, hasAll = false;

  roleSettings = roleSettings || {};

  // check local permissions
  role.populate('permissions.permission', function (err, role) {
    if (err) return done(err);
    if (role.permissions) {
      permissionNames.some(function (pn) {
        var perms = [], has = false;
        role.permissions.some(function (p) {
          if (p.permission.name === pn) {
            var settings = p.settings || {};
            if (p.settingsFactory) {
              settings = p.settingsFactory(roleSettings);
            }
            perms.push(settings);
            has = true;
            if (!needPermissions) return true; // quit on first hit
          }
          return false;
        });
        perms = mergePermissions(foundPermissions[pn], perms);
        if (perms) {
          foundPermissions[pn] = perms;
        }
        return !needPermissions && has; // quit on first hit
      });
    }
    hasAll = checkHasAll();

    // check nested roles
    role.populate('roles.role', function (err, obj) {
      if (err) return done(err);
      if (obj.roles) {
        var iter = 0;
        async.until(
          function () {
            return (hasAll && !needPermissions) || iter === obj.roles.length;
          },
          function (next) {
            var childRole = obj.roles[iter];
            var settings = childRole.settings || {};
            if (childRole.settingsFactory) {
              settings = childRole.settingsFactory(roleSettings);
            }

            doCan.call(childRole.role, settings, type, permissionNames, needPermissions, function (err, has, permissions) {
              if (err) return next(err);
              if (permissions) {
                foundPermissions = mergePermissionSets(foundPermissions, permissions);
              }
              hasAll = hasAll || !!has || checkHasAll();
              iter++;
              next();
            });
          },
          function (err) {
            if (err) return done(err, hasAll, foundPermissions);
            return done(null, hasAll, foundPermissions);
          }
        );
      }
      else {
        return done(null, hasAll, foundPermissions);
      }
    });
  });


  function checkHasAll() {
    return (type === CAN_ANY) ?
      permissionNames.some(function (pn) {
        var p = foundPermissions[pn];
        return p && p.length > 0;
      }) :
      permissionNames.every(function (pn) {
        var p = foundPermissions[pn];
        return p && p.length > 0;
      });
  }
}

function mergePermissions(perms1, perms2) {
  if (!perms1) return perms2.length ? perms2 : null;

  var existing = {};
  perms1.forEach(function (p1) {
    existing[JSON.stringify(p1)] = 1;
  });

  perms2.forEach(function (p2) {
    var key = JSON.stringify(p2);
    if (!existing.hasOwnProperty(key)) {
      perms1.push(p2);
    }
  });

//  var existing = {};
//  var i1 = perms1.length;
//  if (!i1) return perms2;
//  while (i1--) {
//    existing[perms1[i1]] = 1;
//  }
//  i1 = perms2.length;
//  while (i1--) {
//    var val = perms2[i1];
//    if (existing.hasOwnProperty(val)) continue;
//    perms1.push(val);
//  }
  return perms1;
}

function mergePermissionSets(set1, set2) {
  var key, val;
  for (key in set1) {
    if (set1.hasOwnProperty(key)) {
      val = set2[key];
      if (val) {
        set1[key] = mergePermissions(set1[key], val);
      }
    }
  }
  for (key in set2) {
    if (set2.hasOwnProperty(key)) {
      val = set1[key];
      if (!val) {
        set1[key] = set2[key];
      }
    }
  }
  return set1;
}

function resolveRole(role, done) {
  if (typeof role === 'string') {
    mongoose.model('Role').findOne({ name: role }, function (err, role) {
      if (err) return done(err);
      if (!role) return done(new Error("Unknown role"));
      done(null, role);
    });
  }
  else {
    done(null, role);
  }
}

function resolveRoleById(role, done) {
  if (role instanceof mongoose.Types.ObjectId) {
    mongoose.model('Role').findById(role.toString(), function (err, role) {
      if (err) return done(err);
      if (!role) return done(new Error("Unknown role"));
      done(null, role);
    });
  }
  else {
    done(null, role);
  }
}

function firstRole(role, options, done) {
  if ('function' === typeof options) {
    done = options;
    options = {};
  }
  options = extend({
    recursive: true,
    settings: null,
    settingsFactory: null
  }, options);

  var obj = this;
  resolveRole(role, function (err, role) {
    if (err) return done(err);
    var first = null, iter = 0;
    async.until(
      function () {
        return first || iter == obj.roles.length;
      },
      function (next) {
        var existing = obj.roles[iter];
        iter++;
        if (((existing.role._id && existing.role._id.equals(role._id)) ||
          (existing.role.toString() === role.id)) &&
          (!options.settings || !diff(options.settings, existing.settings || {})) &&
          (!options.settingsFactory || (existing.settingsFactory && (options.settingsFactory.toString() == existing.settingsFactory.toString())))) {
          first = existing;
          next();
        } else if (!options.recursive) {
          next();
        } else {
          resolveRoleById(existing.role, function (err, _existing) {
            if (err) return next(err);
            firstRole.call(_existing, role, options, function (err, existing) {
              if (err) return next(err);
              first = existing;
              next();
            });
          });
        }
      },
      function (err) {
        done(err, first);
      }
    )
  });
}

function hasRole(role, options, done) {
  if ('function' === typeof options) {
    done = options;
    options = {};
  }

  firstRole.call(this, role, options, function (err, role) {
    if (err) return done(err);
    done(null, role != null);
  });
}

function addRole(role, settings, done) {
  if ('function' === typeof settings) {
    if (done && !(this instanceof Role)) return done(new Error('Can not add templated role to user'));
    if (done == null) {
      done = settings;
      settings = null;
    }
  }

  var obj = this;
  resolveRole(role, function (err, role) {
    if (err) return done(err);
    obj.canAddRole(role, settings, function (err, canAdd, noRecursion) {
      if (err) return done(err);
      if (!canAdd) {
        if (!noRecursion) return done(new Error('Recursive role nesting detected'));
        return done(null, obj);
      }
      var newRole = { role: role._id };
      if (settings != null) {
        if ('function' === typeof settings) {
          newRole.settingsFactory = settings;
        } else {
          newRole.settings = settings;
        }
      }
      obj.roles.push(newRole);
      obj.save(done);
    });
  });
}

function canAddRole(role, settings, done) {
  if (('function' === typeof settings) && (done == null)) {
    done = settings;
    settings = null;
  }

  var obj = this;
  resolveRole(role, function (err, role) {
    if (err) return done(err);
    if (obj._id.equals(role._id)) {
      return done(null, false, false);
    }
    var options = { recursive: false };
    if ('function' === typeof settings) {
      options.settingsFactory = settings;
    } else {
      options.settings = settings || {};
    }
    obj.hasRole(role, options, function (err, has) {
      if (err) return done(err);
      if (has) return done(null, false, true);
      if (obj instanceof Role) {
        testRecursion(obj, role, function (err, hasRecursion) {
          if (err) return done(err);
          done(null, !hasRecursion);
        });
      } else {
        done(null, true);
      }
    });
  });
}

function removeRole(role, settings, done) {
  if (('function' === typeof settings) && (done == null)) {
    done = settings;
    settings = null;
  }

  var obj = this;
  resolveRole(role, function (err, role) {
    var options = { role: role._id };
    if (settings != null) {
      if ('function' === typeof settings) {
        options.settingsFactory = settings;
      } else {
        options.settings = settings;
      }
    }
    firstRole.call(obj, role.name, options, function (err, existing) {
      if (err) return done(err);
      if (existing == null) return done(null);
      obj.roles.splice(obj.roles.indexOf(existing), 1);
      obj.save(done);
    });
  });
}

function resolvePermission(permission, done) {
  if (typeof permission === 'string') {
    mongoose.model('Permission').findOne({ name: permission }, function (err, permission) {
      if (err) return done(err);
      if (!permission) return done(new Error("Unknown permission"));
      done(null, permission);
    });
  }
  else {
    done(null, permission);
  }
}

function firstPermission(permission, options, done) {
  if ('function' === options) {
    done = options;
    options = {};
  }
  options = extend({
    settings: null,
    settingsFactory: null
  }, options);

  var obj = this;
  resolvePermission(permission, function (err, permission) {
    if (err) return done(err);
    var first = null, iter = 0;
    async.until(
      function () {
        return first || iter == obj.permissions.length;
      },
      function (next) {
        var existing = obj.permissions[iter];
        iter++;
        if (((existing.permission._id && existing.permission._id.equals(permission._id)) ||
          (existing.permission.toString() === permission.id)) &&
          (!options.settings || !diff(options.settings, existing.settings || {})) &&
          (!options.settingsFactory || (existing.settingsFactory && (options.settingsFactory.toString() == existing.settingsFactory.toString())))) {
          first = existing;
          next();
        } else {
          next();
        }
      },
      function (err) {
        done(err, first);
      }
    )
  });
}

function hasPermission(permission, options, done) {
  if ('function' === typeof options) {
    done = options;
    options = {};
  }

  firstPermission.call(this, permission, options, function (err, permission) {
    if (err) return done(err);
    done(null, permission != null);
  });
}

function addPermission(permission, settings, done) {
  if ('function' === typeof settings) {
    if (done && !(this instanceof Role)) return done(new Error('Can not add templated permission to user'));
    if (done == null) {
      done = settings;
      settings = null;
    }
  }

  var obj = this;
  resolvePermission(permission, function (err, permission) {
    if (err) return done(err);
    var options = {};
    if ('function' === typeof settings) {
      options.settingsFactory = settings;
    } else {
      options.settings = settings || {};
    }
    hasPermission.call(obj, permission, options, function (err, has) {
      if (err) return done(err);
      if (has) return done(null, obj);
      var newPermission = extend({ permission: permission._id }, options);
      obj.permissions.push(newPermission);
      obj.save(done);
    });
  });
}

function removePermission(permission, settings, done) {
  if (('function' === typeof settings) && (done == null)) {
    done = settings;
    settings = null;
  }

  var obj = this;
  resolvePermission(permission, function (err, permission) {
    var options = {};
    if ('function' === typeof settings) {
      options.settingsFactory = settings;
    } else {
      options.settings = settings || {};
    }
    firstPermission.call(obj, permission.name, options, function (err, existing) {
      if (err) return done(err);
      if (existing == null) return done(null);
      obj.permissions.splice(obj.permissions.indexOf(existing), 1);
      obj.save(done);
    });
  });
}

function plugin(schema) {
  schema.add({
    roles: [DecoratedRoleSchema],
    permissions: [DecoratedPermissionSchema]
  });

  schema.methods.hasRole = hasRole;

  schema.methods.canAddRole = canAddRole;

  // TODO: add grantor + datetime
  schema.methods.addRole = addRole;

  // TODO: keep history
  schema.methods.removeRole = removeRole;

  schema.methods.addPermission = addPermission;

  schema.methods.removePermission = removePermission;

  schema.methods.populateRoles = function (resolveSettings, done) {
    this.populate('role.roles', function (err, obj) {
      if (err) return done(err);
      if (resolveSettings) {
        async.forEachSeries(obj.roles, function (role, next) {
          role.role.resolveSettings(role.settings, function (err) {
              if (err) return next(err);
              next();
            },
            function (err) {
              return done(err);
            })
        })
      } else {
        done(null, obj);
      }
    })
  };

  schema.methods.can = function (permissionName, done) {
    doCan.call(this, null, CAN_ALL, [permissionName], true, function (err, has, permissions) {
      if (err) return done(err);
      if (permissions) {
        permissions = permissions[permissionName];
      }
      done(null, has, permissions);
    });
  };

  schema.methods.canAll = function (permissionNames, done) {
    doCan.call(this, null, CAN_ALL, permissionNames, true, done);
  };

  schema.methods.canAny = function (permissionNames, needPermissions, done) {
    if ('function' === typeof needPermissions) {
      done = needPermissions;
      needPermissions = false;
    }

    doCan.call(this, null, CAN_ANY, permissionNames, needPermissions, done);
  };
}

function init(rolesAndPermissions, done) {
  var count = Object.keys(rolesAndPermissions).length
    , roles = []
    , promise = new mongoose.Promise(done);
  for (var name in rolesAndPermissions) {
    if (rolesAndPermissions.hasOwnProperty(name)) {
      var len, role;
      // Convert [action, subject] arrays to objects
      len = rolesAndPermissions[name].length;
      for (var i = 0; i < len; i++) {
        if ('string' === typeof rolesAndPermissions[name][i]) {
          rolesAndPermissions[name][i] = {
            name: rolesAndPermissions[name][i]
          };
        }
      }

      // Create role
      role = new Role({name: name});
      roles.push(role);
      role.save(function (err, role) {
        if (err) return promise.error(err);
        // Create role's permissions if they do not exist
        Permission.findOrCreate(rolesAndPermissions[role.name], function (err) {
          if (err) return promise.error(err);
          // Add permissions to role
          role.permissions = Array.prototype.slice.call(arguments, 1);
          // Save role
          role.save(function (err) {
            if (err) return promise.error(err);
            --count || done.apply(null, [err].concat(roles));
          });
        });
      });
    }
  }
}


function getDecoration(decorations, name) {
  var results = null;
  if (decorations && decorations.length) {
    results = [];
    decorations.some(function (decoration) {
      var val = decoration[name];
      if (!val) {
        results = null;
        return true;
      }
      results.push(val);
      return false;
    });
  }
  return results;
}

var saved$__where = mongoose.Model.prototype.$__where;

mongoose.Model.prototype.$__where = function (where) {
  var result = saved$__where.call(this, where);
  if (this._acl && this._acl.length) {
    var conditions = this._acl.length == 1 ? this._acl[0] : { $or: this._acl };
    result = { $and: [result, conditions] };
    delete this._acl;
  }

  return result;
};

var savedExec = Query.prototype.exec;

Query.prototype.exec = function exec(op, callback) {
  var qry = this;
  if (qry._acl && qry._acl.length) {
    var conditions = qry._acl.length == 1 ? qry._acl[0] : { $or: qry._acl };
    if (qry._conditions.$and) {
      qry._conditions.$and.push(conditions);
    } else {
      qry = qry.where({$and: [conditions] });
    }
  }
  savedExec.apply(qry, arguments);
};

Query.prototype.aclFilter = function (permissions) {
  var permissionName = 'read@' + this.model.modelName,
    decorations = permissions[permissionName],
    acl = getDecoration(decorations, 'conditions');
  if (acl) {
    this._acl = acl;
  }
  return this;
};

function aclPlugin(schema) {
  schema.statics.aclCreate = function (permissions, doc, fn) {
    var permissionName = 'create@' + this.modelName,
      decorations = permissions[permissionName],
      acl = getDecoration(decorations, 'presets'),
      err = null;
    if (acl) {
      if (Array.isArray(doc)) {
        doc.some(function (d) {
          err = handlePresets.call(d, acl);
          return err != null;
        });
      } else {
        err = handlePresets.call(doc, acl);
      }
    }
    if (err) {
      var promise = new mongoose.Promise();
      if ('function' == typeof fn) {
        promise.onResolve(fn);
      }
      promise.error(err);
      return promise;
    }

    return this.create.call(this, doc, fn);
  };

  schema.statics.aclUpdate = function (permissions, conditions, doc, options, callback) {
    var args = Array.prototype.slice.call(arguments),
      permissionName = 'update@' + this.modelName,
      decorations = permissions[permissionName],
      _conditions = getDecoration(decorations, 'conditions');
    args.shift();
    if (_conditions) {

      var
        callbackArg = args[args.length - 1],
        hasCallback = ('function' === typeof callbackArg);
      if (hasCallback) {
        args.splice(-1, 1);
      }
      var qry = this.update.apply(this, args);
      qry._acl = _conditions;
      if (hasCallback) {
        return qry.exec(callbackArg);
      }
      return qry;
    }

    return this.update.apply(this, args);
  };

  schema.statics.aclRemove = function (permissions, conditions, callback) {
    var args = Array.prototype.slice.call(arguments),
      permissionName = 'delete@' + this.modelName,
      decorations = permissions[permissionName],
      _conditions = getDecoration(decorations, 'conditions');
    args.shift();
    if (_conditions) {
      var
        callbackArg = args[args.length - 1],
        hasCallback = ('function' === typeof callbackArg);
      if (hasCallback) {
        args.splice(-1, 1);
      }
      var qry = this.remove.apply(this, args);
      qry._acl = _conditions;
      if (hasCallback) {
        return qry.exec(callbackArg);
      }
      return qry;
    }

    return this.remove.apply(this, args);
  };



  schema.methods.aclSave = function (permissions, fn) {
    var permissionName = (this.isNew ? 'create' : 'update') + '@' + this.constructor.modelName,
      decorations = permissions[permissionName],
      presets = getDecoration(decorations, 'presets');
    if (presets) {
      var err = handlePresets.call(this, presets);
      if (err) {
        var promise = new mongoose.Promise();
        if ('function' == typeof fn) {
          promise.onResolve(fn);
        }
        promise.error(err);
        return promise;
      }
    }

    if (!this.isNew) {
      var conditions = getDecoration(decorations, 'conditions');
      if (conditions) {
        this._acl = conditions;

        var savedFn = fn;
        fn = function (err, obj, cnt) {
          if (!err && !cnt) {
            return savedFn.call(this, new Error('not authorized'));
          }
          savedFn.apply(this, arguments);
        }
      }
    }

    return this.save.call(this, fn);
  };

  schema.methods.aclRemove = function (permissions, fn) {
    var self = this;
    // Need to call the static method to be able to detect whether it was processed (and thus authorized)
    return this.constructor.aclRemove(permissions, {_id: this._id}, function(err, cnt) {
      if (!err && !cnt) {
        return fn.call(this, new Error('not authorized'));
      }
      fn.call(this, null, self);
    });

//    var permissionName = 'delete@' + this.constructor.modelName,
//      decorations = permissions[permissionName],
//      conditions = getDecoration(decorations, 'conditions');
//    if (conditions) {
//      this._acl = conditions;
//
//      var savedFn = fn;
//      fn = function (err, obj, cnt) {
//        if (!err && !obj) {
//          return savedFn.call(this, new Error('not authorized'));
//        }
//        savedFn.apply(this, arguments);
//      }
//    }
//
//    return this.remove.call(this, fn);
  };


  function checkPresets(presets) {
    var result = {
      match: true,
      empty: true
    };
    for (var key in presets) {
      if (presets.hasOwnProperty(key)) {
        var val = this[key],
          preset = presets[key];
        if (val) {
          if ('object' === typeof val) {
            var res = checkPresets.call(val, preset);
            result.match = result.match && res.match;
            result.empty = result.empty && res.empty;
          } else {
            result.empty = false;
            result.match = result.match && (val == preset);
          }
        } else {
          result.match = !preset;
        }
      }
      if (!result.match && !result.empty) {
        return result;
      }
    }
    return result;
  }

  function setPresets(presets) {
    for (var key in presets) {
      if (presets.hasOwnProperty(key)) {
        var val = this[key],
          preset = presets[key];
        if (val) {
          if ('object' === typeof val) {
            setPresets.call(val, preset);
          }
        } else {
          this[key] = preset;
        }
      }
    }
  }

  function handlePresets(acl) {
    var obj = this,
      result = null;

    acl = acl.length == 1 ? acl[0] : acl;
    if (Array.isArray(acl)) {
      var ok = acl.some(function (presets) {
        return checkPresets.call(obj, presets).match;
      });

      if (!ok) {
        result = new Error('not authorized');
      }
    } else {
      var res = checkPresets.call(obj, acl);
      if (!res.match) {
        if (!res.empty) {
          result = new Error('not authorized');
        }
        setPresets.call(obj, acl);
      }
    }
    return result;
  }


}


module.exports.Permission = Permission = mongoose.model('Permission', PermissionSchema);
module.exports.Role = Role = mongoose.model('Role', RoleSchema);
module.exports.plugin = plugin;
module.exports.aclPlugin = aclPlugin;
module.exports.init = init;
