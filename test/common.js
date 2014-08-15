var mongoose = require('mongoose')
  , rbac = require('../')
  , Permission = rbac.Permission
  , Role = rbac.Role
  , UserSchema
  , User;

process.env.NODE_ENV = 'test';

function setup(uri, callback) {
  mongoose.set('debug', true);
  mongoose.connect(uri);
  mongoose.connection.on('err', function () {
    callback(new Error("connection error"));
  });
  mongoose.connection.once('open', function () {
    reset(callback);
  });
}

function empty(callback) {
  User.remove({});
  Role.remove({});
  Permission.remove({});
  callback();
}

function reset(callback) {
  for (var name in mongoose.connection.collections) {
    mongoose.connection.collections[name].drop();
  }
  callback();
}

function loadFixtures(callback) {
  empty(function (err) {
    if (err) return callback(err);

    var permissions = [
      'create@Post',
      'read@Post',
      'update@Post',
      'delete@Post',
      'create@Comment',
      'read@Comment',
      'update@Comment',
      'delete@Comment',
      'read@Foo'
    ].map(function (item) {
        return { name: item };
      });

    var user = new User({ username: 'henry' });
    user.save();

    Permission.create(permissions, function (err) {
      if (err) return callback(err);

      var perms, admin, readonly, guest;

      perms = Array.prototype.slice.call(arguments, 1);
      admin = new Role({ name: 'admin' });
      admin.permissions = perms.slice(0,-1).map(mapPermission);
      admin.save(function (err) {
        if (err) return callback(err);
        readonly = new Role({ name: 'readonly' });
        readonly.permissions = [perms[1], perms[5], perms[8]].map(mapPermission);
        readonly.save(function (err) {
          if (err) return callback(err);
          guest = new Role({name: 'guest'});
          guest.save(function (err) {
            callback(err);
          });
        });
      });
    });
  });

  function mapPermission(p) {
    return {
      permission: p
    };
  }
}

UserSchema = mongoose.Schema({ username: String });
UserSchema.plugin(rbac.plugin);
User = mongoose.model('User', UserSchema);

module.exports.User = User;
module.exports.setup = setup;
module.exports.empty = empty;
module.exports.reset = reset;
module.exports.loadFixtures = loadFixtures;
