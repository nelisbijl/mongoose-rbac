var mongoose = require('mongoose')
  , async = require('async')
  , CAN_ALL = 'all'
  , CAN_ANY = 'any'
  , PermissionSchema
  , Permission
  , RoleSchema
  , Role;

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

RoleSchema = mongoose.Schema({
  name: { type: String, required: true },
  displayName: String,
  description: String,
  roles: [{
      role:{ type: mongoose.Schema.Types.ObjectId, ref: 'Role' },
      settings: mongoose.Schema.Types.Mixed
  }],
  permissions: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Permission' }]
});

RoleSchema.methods.hasRole = function (role, childsOnly, done) {
  if ('function' === childsOnly) {
    done = childsOnly;
    childsOnly = false;
  }

  var obj = this;
  resolveRole(role, function (err, role) {
    if (err) return done(err);
    var hasRole = false, iter = 0;
    async.until(
      function () {
        return hasRole || iter == obj.roles.length;
      },
      function (next) {
        var existing = obj.roles[iter].role;
        iter++;
        if ((existing._id && existing._id.equals(role._id)) ||
          (existing.toString() === role.id)) {
          hasRole = true;
          next();
        } else if (childsOnly) {
          next();
        } else {
          resolveRoleById(existing, function(err, _existing) {
            if (err) return next(err);
            _existing.hasRole(role, childsOnly, function (err, has) {
              if (err) return next(err);
              hasRole = has;
              next();
            });
          });
        }
      },
      function  (err) {
        done(err, hasRole);
      }
    )
  });
};

RoleSchema.methods.canAddRole = function (role, done) {
  var obj = this;
  resolveRole(role, function (err, role) {
    if (err) return done(err);
    obj.hasRole(role, true, function (err, has) {
      if (err) return done(err);
      if (has) return done(null, obj);
      testRecursion(obj, role, function (err, hasRecursion) {
        if (err) return done(err);
        done(null, !hasRecursion);
      });
    });
  });
};

// TODO: add grantor + datetime
RoleSchema.methods.addRole = function (role, done) {
  var obj = this;
  resolveRole(role, function (err, role) {
    if (err) return done(err);
    obj.canAddRole(role, function (err, canAdd) {
      if (err) return done(err);
      if (!canAdd) return done(new Error('Recursive role nesting detected'));
      var newRole = { role: role._id };
      obj.roles.push(newRole);
      //obj.roles = [role._id].concat(obj.roles);
      obj.save(done);
    });
  });
};

// TODO: keep history
RoleSchema.methods.removeRole = function (role, done) {
  var obj = this;
  resolveRole(role, function (err, role) {
    obj.hasRole(role.name, true, function (err, has) {
      if (err) return done(err);
      if (!has) return done(null);
      var index = obj.roles.indexOf(role._id);
      obj.roles.splice(index, 1);
      obj.save(done);
    });
  });
};

RoleSchema.methods.can = function (permissionName, done) {
  mongoose.model('Role').findById(this._id, function (err, role) {
    if (err) return done(err);
    doCan.call(role, CAN_ALL, [permissionName], true, done);
  });
};

RoleSchema.methods.canAll = function (permissionNames, done) {
  mongoose.model('Role').findById(this._id, function (err, role) {
    if (err) return done(err);
    doCan.call(role, CAN_ALL, permissionNames, true, done);
  });
};

RoleSchema.methods.canAny = function (permissionNames, needPermissions, done) {
  if ('function' === typeof needPermissions) {
    done = needPermissions;
    needPermissions = false;
  }

  mongoose.model('Role').findById(this._id, function (err, role) {
    if (err) return done(err);
    doCan.call(role, CAN_ANY, permissionNames, needPermissions, done);
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

function doCan(type, permissionNames, needPermissions, done) {
  var role = this;

  var foundPermissions = {}, hasPerm = false;

  role.populate('roles.role', function (err, obj) {
    if (err) return done(err);
    if (obj.roles) {
      var iter = 0;
      async.until(
        function () {
          return (hasPerm && !needPermissions) || iter === obj.roles.length;
        },
        function (next) {
          var childRole = obj.roles[iter].role;
          doCan.call(childRole, type, permissionNames, needPermissions, function (err, has, permissions) {
            if (err) return next(err);
            hasPerm = !!has;
            if (permissions) {
              foundPermissions = mergePermissionSets(foundPermissions, permissions);
            }
            iter++;
            next();
          });
        },
        function (err) {
          if (err) return done(err, hasPerm, foundPermissions);
          if (hasPerm && !needPermissions) return done(null, hasPerm, foundPermissions);
          thisDoCan();
        }
      );
    }
    else {
      thisDoCan();
    }
  });

  function thisDoCan() {
    foundPermissions = foundPermissions || {};
    role.populate('permissions', function (err, role) {
      if (err) return done(err);
      var hasAll = false;
      if (role.permissions) {
        permissionNames.forEach(function (pn) {
          var perms = [];
          var has = false;
          role.permissions.forEach(function (p) {
            if (p.name === pn) {
              has = true;
              perms.push(p);
            }
          });
          foundPermissions[pn] = mergePermissions(foundPermissions[pn], perms);
        });
      }
      if (type === CAN_ANY) {
        hasAll = permissionNames.some(function (pn) {
          var p = foundPermissions[pn];
          return p && p.length > 0;
        });
      }
      else {
        hasAll = permissionNames.every(function (pn) {
          var p = foundPermissions[pn];
          return p && p.length > 0;
        });
      }
      done(null, hasAll, foundPermissions);
    });
  }
}

function mergePermissions(perms1, perms2) {
  if (!perms1) return perms2;
  var existing = {}, result = [];
  var i1 = perms1.length;
  if (!i1) return perms2;
  while (i1--) {
    existing[perms1[i1]] = 1;
  }
  i1 = perms2.length;
  while(i1--) {
    var val = perms2[i1];
    if (existing.hasOwnProperty(val)) continue;
    perms1.push(val);
  }
  return perms1;
}

function mergePermissionSets(set1, set2) {
  var key, val;
  for (key in set1) {
    val = set2[key];
    if (val) {
      set1[key] = mergePermissions(set1[key], val);
    }
  }
  for (key in set2) {
    val = set1[key];
    if (!val) {
      set1[key] = set2[key];
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


function plugin(schema, options) {
  options || (options = {});

  schema.add({
    //roles: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Role' }],
    roles: [{
      role: { type: mongoose.Schema.Types.ObjectId, ref: 'Role' },
      settings: mongoose.Schema.Types.Mixed
    }],
    permissions: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Permission' }]
  });

  schema.methods.hasRole = function (role, childsOnly, done) {
    if ('function' === typeof childsOnly) {
      done = childsOnly;
      childsOnly = false;
    }

    var obj = this;
    resolveRole(role, function (err, role) {
      if (err) return done(err);
      var hasRole = false, iter = 0;
      async.until(
        function () {
          return hasRole || iter == obj.roles.length;
        },
        function (next) {
          var existing = obj.roles[iter].role;
          iter++;
          if ((existing._id && existing._id.equals(role._id)) ||
            (existing.toString() === role.id)) {
            hasRole = true;
            next();
          } else if (childsOnly) {
            next();
          } else {
            resolveRoleById(existing, function(err, _existing) {
              if (err) return next(err);
              _existing.hasRole(role, childsOnly, function (err, has) {
                if (err) return next(err);
                hasRole = has;
                next();
              });
            });
          }
        },
        function  (err) {
          done(err, hasRole);
        }
      )
    });
  };

  // TODO: add grantor + datetime
  schema.methods.addRole = function (role, done) {
    var obj = this;
    resolveRole(role, function (err, role) {
      if (err) return done(err);
      obj.hasRole(role, true, function (err, has) {
        if (err) return done(err);
        if (has) return done(null, obj);
        var newRole = { role: role._id };
        obj.roles.push(newRole);
        //obj.roles = [role._id].concat(obj.roles);
        obj.save(done);
      });
    });
  };

  // TODO: keep history
  schema.methods.removeRole = function (role, done) {
    var obj = this;
    resolveRole(role, function (err, role) {
      obj.hasRole(role.name, true, function (err, has) {
        if (err) return done(err);
        if (!has) return done(null);
        var index = obj.roles.indexOf(role._id);
        obj.roles.splice(index, 1);
        obj.save(done);
      });
    });
  };

  schema.methods.can = function (permissionName, done) {
    var obj = this;
    obj.populate('roles.role', function (err, obj) {
      if (err) return done(err);
      var hasPerm = false, foundPermissions = [];
      if (obj.roles) {
        async.forEachSeries(obj.roles, function (role, next) {
          role.role.can(permissionName, function (err, has, permissions) {
            if (err) return next(err);
            if (has) hasPerm = true;
            if (permissions) {
              foundPermissions = mergePermissions(foundPermissions, permissions[permissionName]);
            }
            next();
          });
        }, function (err) {
          done(err, hasPerm, foundPermissions);
        });
      }
      else {
        done(null, hasPerm, foundPermissions);
      }
    });
  };

  schema.methods.canAll = function (permissionNames, done) {
    var obj = this;
    obj.populate('roles.role', function (err, obj) {
      if (err) return done(err);
      var hasAll = false, foundPermissions = {};
      if (obj.roles) {
        async.forEachSeries(permissionNames, function (pn, nextPerm) {
          var actionPermissions = [];
          async.forEachSeries(obj.roles, function (role, nextRole) {
            role.role.can(pn, function (err, has, permissions) {
              if (err) return nextRole(err);
              if (permissions != null) {
                actionPermissions = mergePermissions(actionPermissions, permissions[pn]);
              }
              nextRole();
            });
          }, function (err) {
            foundPermissions[pn] = actionPermissions;
            nextPerm(err);
          });
        }, function (err) {
          hasAll = permissionNames.every(function (pn) {
            var p = foundPermissions[pn];
            return p && p.length > 0;
          });
          done(err, hasAll, foundPermissions);
        });
      }
      else {
        done(null, hasAll, foundPermissions);
      }
    });
  };

  schema.methods.canAny = function (permissionNames, needPermissions, done) {
    if ('function' === typeof needPermissions) {
      done = needPermissions;
      needPermissions = false;
    }

    var obj = this;
    obj.populate('roles.role', function (err, obj) {
      if (err) return done(err);
      var hasAny = false, foundPermissions = [];
      if (obj.roles) {
        var iter = 0;
        async.until(
          function () {
            return (hasAny && !needPermissions) || iter === obj.roles.length;
          },
          function (callback) {
            obj.roles[iter].role.canAny(permissionNames, needPermissions, function (err, has, permissions) {
              if (err) return callback(err);
              if (has) hasAny = true;
              if (permissions) {
                foundPermissions = mergePermissionSets(foundPermissions, permissions)
              }
              iter++;
              callback();
            });
          },
          function (err) {
            done(err, hasAny, foundPermissions);
          });
      }
      else {
        done(null, hasAny, foundPermissions);
      }
    });
  };
}

function init(rolesAndPermissions, done) {
  var count = Object.keys(rolesAndPermissions).length
    , roles = []
    , promise = new mongoose.Promise(done);
  for (var name in rolesAndPermissions) {
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
    role = new Role({ name: name });
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

Array.prototype.distinct = function(){
  var u = {}, a = [];
  for(var i = 0, l = this.length; i < l; ++i){
    if(u.hasOwnProperty(this[i])) {
      continue;
    }
    a.push(this[i]);
    u[this[i]] = 1;
  }
  return a;
};

module.exports.Permission = Permission = mongoose.model('Permission', PermissionSchema);
module.exports.Role = Role = mongoose.model('Role', RoleSchema);
module.exports.plugin = plugin;
module.exports.init = init;
