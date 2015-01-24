/* global describe,it,before,beforeEach,afterEach */

var chai = require('chai')
  , mongoose = require('mongoose')
  , expect = chai.expect
  , rbac = require('../')
  , common = require('./common')
  , step = require('step')
  , Role = rbac.Role
  , Permission = rbac.Permission
  , User = common.User
  , Contact = common.Contact;

chai.use(require('chai-fuzzy'));

before(function (next) {
  common.setup('mongodb://localhost/rbac_test', next);
});

describe('roles and permissions:', function () {
  var henry, admin, guest;

  beforeEach(function (next) {
    common.loadFixtures(function (err) {
      if (err) return next(err);
      User.findOne({ username: 'henry' }).populate('roles').exec(function (err, user) {
        if (err) return next(err);
        henry = user;
        Role.findOne({name: 'admin'}, function (err, role) {
          admin = role;
          Role.findOne({name: 'guest'}, function (err, role) {
            guest = role;
            next();
          });
        });
      });
    });
  });

  afterEach(function (next) {
    common.reset(next);
  });

  describe('initialization:', function () {
    it('should batch create roles and permissions', function (next) {
      rbac.init({
        role1: [
          'create@Post',
          'read@Post',
          'update@Post',
          'delete@Post'
        ],
        role2: [
          'read@Post'
        ],
        role3: [
          'read@Post',
          'update@Post'
        ]
      }, function (err, role1, role2, role3) {
        expect(err).to.not.exist;
        expect(role1.permissions).to.have.length(4);
        expect(role2.permissions).to.have.length(1);
        expect(role3.permissions).to.have.length(2);
        next();
      });
    });
  });

  describe('role', function () {
    describe('create', function () {
      it('should require a unique role name', function (next) {
        Role.create({ name: 'admin' }, function (err) {
          expect(err.message).to.equal('Role name must be unique');
          next();
        });
      });
    });

    describe('addRole', function () {
      it('should add a role to a role', function (done) {
        admin.addRole('readonly', function (err) {
          expect(err).to.not.exist;
          expect(admin.roles).to.have.length(1);
          Role.findOne({ name: 'readonly' }, function (err, role) {
            expect(err).to.not.exist;
            expect(admin.roles[0].role.equals(role._id)).to.be.ok;
            done();
          });
        });
      });

      it('should ignore duplicate role', function (done) {
        admin.addRole('readonly', function (err) {
          expect(err).to.not.exist;
          expect(admin.roles).to.have.length(1);
          admin.addRole('readonly', function (err) {
            expect(err).to.not.exist;
            expect(admin.roles).to.have.length(1);
            Role.findOne({ name: 'readonly' }, function (err, role) {
              expect(err).to.not.exist;
              expect(admin.roles[0].role.equals(role._id)).to.be.ok;
              done();
            });
          });
        });
      });

      it('should allow duplicate role with different decoration', function (done) {
        admin.addRole('readonly', function (err) {
          expect(err).to.not.exist;
          expect(admin.roles).to.have.length(1);
          admin.addRole('readonly', { a: 'A' }, function (err) {
            expect(err).to.not.exist;
            expect(admin.roles).to.have.length(2);
            admin.addRole('readonly', { a: 'B' }, function (err) {
              expect(err).to.not.exist;
              expect(admin.roles).to.have.length(3);
              Role.findOne({ name: 'readonly' }, function (err, role) {
                expect(err).to.not.exist;
                expect(admin.roles[0].role.equals(role._id)).to.be.ok;
                done();
              });
            });
          });
        });
      });

      it('should ignore duplicate role + decoration', function (done) {
        admin.addRole('readonly', {a: 'A'}, function (err) {
          expect(err).to.not.exist;
          expect(admin.roles).to.have.length(1);
          admin.addRole('readonly', { a: 'A' }, function (err) {
            expect(err).to.not.exist;
            expect(admin.roles).to.have.length(1);
            Role.findOne({ name: 'readonly' }, function (err, role) {
              expect(err).to.not.exist;
              expect(admin.roles[0].role.equals(role._id)).to.be.ok;
              done();
            });
          });
        });
      });

      it('should deny add self', function (done) {
        admin.addRole('admin', function (err) {
          expect(err).to.exist;
          expect(err.message).equals('Recursive role nesting detected').to.be.ok;
          done();
        });
      });

      it('should deny role recursion', function (done) {
        admin.addRole('readonly', function (err) {
          expect(err).to.not.exist;
          Role.findOne({ name: 'readonly' }, function (err, role) {
            expect(err).to.not.exist;
            role.addRole('admin', function (err) {
              expect(err).to.exist;
              expect(err.message).equals('Recursive role nesting detected').to.be.ok;
              done();
            });
          });
        });
      });

      it('should deny indirect role recursion', function (done) {
        admin.addRole('readonly', function (err) {
          expect(err).to.not.exist;
          Role.findOne({ name: 'readonly' }, function (err, readonly) {
            expect(err).to.not.exist;
            readonly.addRole('guest', function (err) {
              expect(err).to.not.exist;
              Role.findOne({ name: 'guest' }, function (err, guest) {
                expect(err).to.not.exist;
                guest.addRole('admin', function (err) {
                  expect(err).to.exist;
                  expect(err.message).equals('Recursive role nesting detected').to.be.ok;
                  done();
                });
              });
            });
          });
        });
      });

      it('should allow settings', function (done) {
        admin.addRole('readonly', { a: 'A' }, function (err, obj) {
          expect(err).to.not.exist;
          expect(admin.roles).to.have.length(1);
          expect(obj.roles[0].settings).to.exist;
          expect(obj.roles[0].settings.a).to.equal('A');
          Role.findOne({ name: 'readonly' }, function (err, role) {
            expect(err).to.not.exist;
            expect(admin.roles[0].role.equals(role._id)).to.be.ok;
            done();
          });
        });
      });

      it('should allow multiple roles with same name and different settings', function (done) {
        admin.addRole('readonly', { a: 'A' }, function (err, obj) {
          expect(err).to.not.exist;
          expect(admin.roles).to.have.length(1);
          expect(obj.roles[0].settings).to.exist;
          expect(obj.roles[0].settings.a).to.equal('A');
          admin.addRole('readonly', function (err, obj) {
            expect(err).to.not.exist;
            expect(admin.roles).to.have.length(2);
            expect(obj.roles[1].settings).to.not.exist;
            admin.addRole('readonly', { a: 'B' }, function (err, obj) {
              expect(err).to.not.exist;
              expect(admin.roles).to.have.length(3);
              expect(obj.roles[2].settings).to.exist;
              expect(obj.roles[2].settings.a).to.equal('B');
              Role.find({ name: 'readonly' }, function (err, roles) {
                expect(err).to.not.exist;
                expect(roles).to.exist;
                expect(roles.length).to.equal(1);
                done();
              });
            });
          });
        });
      });

      it('should allow settingsFactory', function (done) {
        var fn = function (opts) {
          return { b: opts.a }
        };
        admin.addRole('readonly', fn, function (err, obj) {
          expect(err).to.not.exist;
          expect(admin.roles).to.have.length(1);
          expect(obj.roles[0].settingsFactory).to.exist;
          expect(JSON.stringify(obj.roles[0].settingsFactory({a: 'A'}))).to.equal(JSON.stringify({b: 'A'}));
          Role.findOne({ name: 'readonly' }, function (err, role) {
            expect(err).to.not.exist;
            expect(admin.roles[0].role.equals(role._id)).to.be.ok;
            Role.findOne({ name: 'admin' }, function (err, role) {
              expect(err).to.not.exist;
              expect(admin.id).to.equals(role.id);
              expect(JSON.stringify(role.roles[0].settingsFactory({a: 'B'}))).to.equal(JSON.stringify({b: 'B'}));
              done();
            });
          });
        });
      });

      it('should deny duplicate settingsFactory', function (done) {
        var fn = function (opts) {
          return { b: opts.a }
        };
        admin.addRole('readonly', fn, function (err) {
          expect(err).to.not.exist;
          admin.addRole('readonly', fn, function (err) {
            expect(err).to.not.exist;
            expect(admin.roles).to.have.length(1);
            done();
          });
        });
      });

    });

    describe('removeRole', function () {
      it('should remove a role from a role', function (done) {
        admin.addRole('readonly', function (err) {
          expect(err).to.not.exist;
          admin.removeRole('readonly', function (err) {
            expect(err).to.not.exist;
            expect(admin.roles).to.be.empty;
            done();
          });
        });
      });

      it('should remove a role from a role with the correct decoration', function (done) {
        var roleA, roleB, role, roleFn;
        var fn = function (opts) {
          return { a: opts.a };
        };
        admin.addRole('readonly', { a: 'A' }, function (err) {
          expect(err).to.not.exist;
          roleA = henry.roles[0];
          admin.addRole('readonly', function (err) {
            expect(err).to.not.exist;
            role = henry.roles[1];
            admin.addRole('readonly', { a: 'B' }, function (err) {
              expect(err).to.not.exist;
              roleB = henry.roles[2];
              admin.addRole('readonly', fn, function (err) {
                expect(err).to.not.exist;
                roleFn = henry.roles[3];
                admin.removeRole('readonly', { a: 'B' }, function (err) {
                  expect(err).to.not.exist;
                  expect(admin.roles.length).to.equal(3);
                  expect(admin.roles.indexOf(roleB)).to.equal(-1);
                  admin.removeRole('readonly', { a: 'A' }, function (err) {
                    expect(err).to.not.exist;
                    expect(admin.roles.length).to.equal(2);
                    expect(admin.roles.indexOf(roleA)).to.equal(-1);
                    admin.removeRole('readonly', fn, function (err) {
                      expect(err).to.not.exist;
                      expect(admin.roles.length).to.equal(1);
                      expect(admin.roles.indexOf(roleFn)).to.equal(-1);
                      admin.removeRole('readonly', function (err) {
                        expect(err).to.not.exist;
                        expect(admin.roles.length).to.be.empty;
                        done();
                      });
                    });
                  });
                });
              });
            });
          });
        });
      });
    });

    describe('addPermission', function () {
      it('should add a permission to a role', function (done) {
        guest.addPermission('read@Post', function (err) {
          expect(err).to.not.exist;
          expect(guest.permissions).to.have.length(1);
          Permission.findOne({ name: 'read@Post' }, function (err, permission) {
            expect(err).to.not.exist;
            expect(guest.permissions[0].permission.equals(permission._id)).to.be.ok;
            done();
          });
        });
      });

      it('should ignore duplicate permission', function (done) {
        guest.addPermission('read@Post', function (err) {
          expect(err).to.not.exist;
          expect(guest.permissions).to.have.length(1);
          guest.addPermission('read@Post', function (err) {
            expect(err).to.not.exist;
            expect(guest.permissions).to.have.length(1);
            Permission.findOne({ name: 'read@Post' }, function (err, permission) {
              expect(err).to.not.exist;
              expect(guest.permissions[0].permission.equals(permission._id)).to.be.ok;
              done();
            });
          });
        });
      });

      it('should allow duplicate permission with different decoration', function (done) {
        guest.addPermission('read@Post', function (err) {
          expect(err).to.not.exist;
          expect(guest.permissions).to.have.length(1);
          guest.addPermission('read@Post', { a: 'A' }, function (err) {
            expect(err).to.not.exist;
            expect(guest.permissions).to.have.length(2);
            guest.addPermission('read@Post', { a: 'B' }, function (err) {
              expect(err).to.not.exist;
              expect(guest.permissions).to.have.length(3);
              Permission.findOne({ name: 'read@Post' }, function (err, permission) {
                expect(err).to.not.exist;
                expect(guest.permissions[0].permission.equals(permission._id)).to.be.ok;
                done();
              });
            });
          });
        });
      });

      it('should ignore duplicate permission + decoration', function (done) {
        guest.addPermission('read@Post', {a: 'A'}, function (err) {
          expect(err).to.not.exist;
          expect(guest.permissions).to.have.length(1);
          guest.addPermission('read@Post', { a: 'A' }, function (err) {
            expect(err).to.not.exist;
            expect(guest.permissions).to.have.length(1);
            Permission.findOne({ name: 'read@Post' }, function (err, permission) {
              expect(err).to.not.exist;
              expect(guest.permissions[0].permission.equals(permission._id)).to.be.ok;
              done();
            });
          });
        });
      });

      it('should allow settings', function (done) {
        guest.addPermission('read@Post', { a: 'A' }, function (err, obj) {
          expect(err).to.not.exist;
          expect(guest.permissions).to.have.length(1);
          expect(obj.permissions[0].settings).to.exist;
          expect(obj.permissions[0].settings.a).to.equal('A');
          Permission.findOne({ name: 'read@Post' }, function (err, permission) {
            expect(err).to.not.exist;
            expect(guest.permissions[0].permission.equals(permission._id)).to.be.ok;
            done();
          });
        });
      });

      it('should allow multiple permissions with same name and different settings', function (done) {
        guest.addPermission('read@Post', { a: 'A' }, function (err, obj) {
          expect(err).to.not.exist;
          expect(guest.permissions).to.have.length(1);
          expect(obj.permissions[0].settings).to.be.like({a: 'A'});
          guest.addPermission('read@Post', function (err, obj) {
            expect(err).to.not.exist;
            expect(guest.permissions).to.have.length(2);
            expect(obj.permissions[1].settings).to.be.like({});
            guest.addPermission('read@Post', { a: 'B' }, function (err, obj) {
              expect(err).to.not.exist;
              expect(guest.permissions).to.have.length(3);
              expect(obj.permissions[2].settings).to.be.like({a: 'B' });
              Permission.find({ name: 'read@Post' }, function (err, permissions) {
                expect(err).to.not.exist;
                expect(permissions).to.exist;
                expect(permissions.length).to.equal(1);
                done();
              });
            });
          });
        });
      });

      it('should allow settingsFactory', function (done) {
        var fn = function (opts) {
          return { b: opts.a }
        };
        guest.addPermission('read@Post', fn, function (err, obj) {
          expect(err).to.not.exist;
          expect(guest.permissions).to.have.length(1);
          expect(obj.permissions[0].settingsFactory).to.exist;
          expect(JSON.stringify(obj.permissions[0].settingsFactory({a: 'A'}))).to.equal(JSON.stringify({b: 'A'}));
          Permission.findOne({ name: 'read@Post' }, function (err, permission) {
            expect(err).to.not.exist;
            expect(guest.permissions[0].permission.equals(permission._id)).to.be.ok;
            Role.findOne({ name: 'guest' }, function (err, role) {
              expect(err).to.not.exist;
              expect(guest.id).to.equal(role.id);
              expect(JSON.stringify(role.permissions[0].settingsFactory({a: 'B'}))).to.equal(JSON.stringify({b: 'B'}));
              done();
            });
          });
        });
      });

      it('should deny duplicate settingsFactory', function (done) {
        var fn = function (opts) {
          return { b: opts.a }
        };
        guest.addPermission('read@Post', fn, function (err) {
          expect(err).to.not.exist;
          guest.addPermission('read@Post', fn, function (err) {
            expect(err).to.not.exist;
            expect(guest.permissions).to.have.length(1);
            done();
          });
        });
      });

    });

    describe('removePermission', function () {
      it('should remove a permission from a role', function (done) {
        guest.addPermission('read@Post', function (err) {
          expect(err).to.not.exist;
          guest.removePermission('read@Post', function (err) {
            expect(err).to.not.exist;
            expect(guest.permissions).to.be.empty;
            done();
          });
        });
      });

      it('should remove a permission from a role with the correct decoration', function (done) {
        var fn = function (opts) {
          return { a: opts.a };
        };
        var pA, pB, p, pFn;
        guest.addPermission('read@Post', { a: 'A' }, function (err) {
          expect(err).to.not.exist;
          pA = guest.permissions[0];
          guest.addPermission('read@Post', function (err) {
            expect(err).to.not.exist;
            p = guest.permissions[1];
            guest.addPermission('read@Post', { a: 'B' }, function (err) {
              expect(err).to.not.exist;
              pB = guest.permissions[2];
              guest.addPermission('read@Post', fn, function (err) {
                expect(err).to.not.exist;
                pFn = guest.permissions[3];
                guest.removePermission('read@Post', { a: 'B' }, function (err) {
                  expect(err).to.not.exist;
                  expect(guest.permissions.length).to.equal(3);
                  expect(guest.permissions.indexOf(pB)).to.equal(-1);
                  guest.removePermission('read@Post', { a: 'A' }, function (err) {
                    expect(err).to.not.exist;
                    expect(guest.permissions.length).to.equal(2);
                    expect(guest.permissions.indexOf(pA)).to.equal(-1);
                    guest.removePermission('read@Post', fn, function (err) {
                      expect(err).to.not.exist;
                      expect(guest.permissions.length).to.equal(1);
                      expect(guest.permissions.indexOf(pFn)).to.equal(-1);
                      guest.removePermission('read@Post', function (err) {
                        expect(err).to.not.exist;
                        expect(guest.permissions.length).to.be.empty;
                        done();
                      });
                    });
                  });
                });
              });
            });
          });
        });
      });
    });
  });

  describe('user', function () {
    describe('addRole', function () {
      it('should add a role to a model', function (next) {
        henry.addRole('admin', function (err) {
          expect(err).to.not.exist;
          expect(henry.roles).to.have.length(1);
          Role.findOne({ name: 'admin' }, function (err, role) {
            expect(henry.roles[0].role.equals(role._id)).to.be.ok;
            next();
          });
        });
      });

      it('should ignore duplicate role', function (done) {
        henry.addRole('admin', function (err) {
          expect(err).to.not.exist;
          expect(henry.roles).to.have.length(1);
          henry.addRole('admin', function (err) {
            expect(err).to.not.exist;
            expect(henry.roles).to.have.length(1);
            Role.findOne({ name: 'admin' }, function (err, role) {
              expect(err).to.not.exist;
              expect(henry.roles[0].role.equals(role._id)).to.be.ok;
              done();
            });
          });
        });
      });

      it('should be able to add multiple roles', function (next) {
        henry.addRole('admin', function (err) {
          expect(err).to.not.exist;
          expect(henry.roles).to.have.length(1);
          henry.addRole('readonly', function (err) {
            expect(err).to.not.exist;
            expect(henry.roles).to.have.length(2);
            next();
          });
        });
      });

      it('should allow settings', function (done) {
        henry.addRole('admin', { a: 'A' }, function (err, obj) {
          expect(err).to.not.exist;
          expect(henry.roles).to.have.length(1);
          expect(obj.roles[0].settings).to.exist;
          expect(obj.roles[0].settings.a).to.equal('A');
          Role.findOne({ name: 'admin' }, function (err, role) {
            expect(err).to.not.exist;
            expect(henry.roles[0].role.equals(role._id)).to.be.ok;
            done();
          });
        });
      });

      it('should allow multiple roles with same name and different settings', function (done) {
        henry.addRole('admin', { a: 'A' }, function (err, obj) {
          expect(err).to.not.exist;
          expect(henry.roles).to.have.length(1);
          expect(obj.roles[0].settings).to.exist;
          expect(obj.roles[0].settings.a).to.equal('A');
          henry.addRole('admin', function (err, obj) {
            expect(err).to.not.exist;
            expect(henry.roles).to.have.length(2);
            expect(obj.roles[1].settings).to.not.exist;
            henry.addRole('admin', { a: 'B' }, function (err, obj) {
              expect(err).to.not.exist;
              expect(henry.roles).to.have.length(3);
              expect(obj.roles[2].settings).to.exist;
              expect(obj.roles[2].settings.a).to.equal('B');
              Role.find({ name: 'admin' }, function (err, roles) {
                expect(err).to.not.exist;
                expect(roles).to.exist;
                expect(roles.length).to.equal(1);
                done();
              });
            });
          });
        });
      });

      it('should reject settingsFactory', function (done) {
        var fn = function (opts) {
          return { a: opts.a }
        };
        henry.addRole('admin', fn, function (err) {
          expect(err).to.exist;
          expect(err.message).equals('Can not add templated role to user').to.be.ok;
          done();
        });
      });
    });

    describe('removeRole', function () {
      it('should remove a role from a model', function (next) {
        henry.addRole('admin', function (err) {
          expect(err).to.not.exist;
          henry.removeRole('admin', function (err) {
            expect(err).to.not.exist;
            expect(henry.roles).to.be.empty;
            next();
          });
        });
      });

      it('should remove a role from a model with the correct decoration', function (done) {
        var roleA, roleB, role;
        henry.addRole('admin', { a: 'A' }, function (err) {
          expect(err).to.not.exist;
          roleA = henry.roles[0];
          henry.addRole('admin', function (err) {
            expect(err).to.not.exist;
            role = henry.roles[1];
            henry.addRole('admin', { a: 'B' }, function (err) {
              expect(err).to.not.exist;
              roleB = henry.roles[2];
              henry.removeRole('admin', { a: 'B' }, function (err) {
                expect(err).to.not.exist;
                expect(henry.roles.length).to.equal(2);
                expect(henry.roles.indexOf(roleB)).to.equal(-1);
                henry.removeRole('admin', { a: 'A' }, function (err) {
                  expect(err).to.not.exist;
                  expect(henry.roles.length).to.equal(1);
                  expect(henry.roles.indexOf(roleA)).to.equal(-1);
                  henry.removeRole('admin', function (err) {
                    expect(err).to.not.exist;
                    expect(henry.roles.length).to.be.empty;
                    done();
                  });
                });
              });
            });
          });
        });
      });

    });

    describe('hasRole', function () {
      it('should indicate whether a model has a given role', function (next) {
        expect(henry.roles).to.be.empty;
        henry.hasRole('admin', function (err, hasAdminRole) {
          expect(err).to.not.exist;
          expect(hasAdminRole).to.equal(false);
          henry.addRole('admin', function (err) {
            expect(err).to.not.exist;
            henry.hasRole('admin', function (err, hasAdminRole) {
              expect(err).to.not.exist;
              expect(hasAdminRole).to.equal(true);
              next();
            });
          });
        });
      });

      it('should indicate whether a model has a given role when roles are populated', function (next) {
        henry.addRole('admin', function (err) {
          expect(err).to.not.exist;
          henry.can('create@Post', function (err, can) {
            expect(err).to.not.exist;
            expect(can).to.equal(true);
            henry.hasRole('admin', function (err, isAdmin) {
              expect(err).to.not.exist;
              expect(isAdmin).to.equal(true);
              next();
            });
          });
        });
      });

      describe('nested role', function () {
        beforeEach(function (done) {
          admin.addRole('readonly', function (err, readonly) {
            expect(err).to.not.exist;
            readonly.addRole('guest', function (err) {
              expect(err).to.not.exist;
              done();
            })
          });
        });

        it('should indicate whether a model has a given role', function (next) {
          expect(henry.roles).to.be.empty;
          henry.hasRole('admin', function (err, hasAdminRole) {
            expect(err).to.not.exist;
            expect(hasAdminRole).to.equal(false);
            henry.addRole('admin', function (err) {
              expect(err).to.not.exist;
              henry.hasRole('readonly', { recursive: false}, function (err, hasReadOnlyRole) { // only direct roles
                expect(err).to.not.exist;
                expect(hasReadOnlyRole).to.equal(false);
                henry.hasRole('readonly', function (err, hasReadOnlyRole) {
                  expect(err).to.not.exist;
                  expect(hasReadOnlyRole).to.equal(true);
                  henry.hasRole('guest', function (err, hasGuestRole) {
                    expect(err).to.not.exist;
                    expect(hasGuestRole).to.equal(true);
                    next();
                  });
                });
              });
            });
          });
        });
      });

    });

    describe('addPermission', function () {
      it('should add a permission to a model', function (next) {
        henry.addPermission('read@Post', function (err) {
          expect(err).to.not.exist;
          expect(henry.permissions).to.have.length(1);
          Permission.findOne({ name: 'read@Post' }, function (err, permission) {
            expect(henry.permissions[0].permission.equals(permission._id)).to.be.ok;
            next();
          });
        });
      });

      it('should ignore duplicate permission', function (done) {
        henry.addPermission('read@Post', function (err) {
          expect(err).to.not.exist;
          expect(henry.permissions).to.have.length(1);
          henry.addPermission('read@Post', function (err) {
            expect(err).to.not.exist;
            expect(henry.permissions).to.have.length(1);
            Permission.findOne({ name: 'read@Post' }, function (err, permission) {
              expect(err).to.not.exist;
              expect(henry.permissions[0].permission.equals(permission._id)).to.be.ok;
              done();
            });
          });
        });
      });

      it('should be able to add multiple permissions', function (next) {
        henry.addPermission('read@Post', function (err) {
          expect(err).to.not.exist;
          expect(henry.permissions).to.have.length(1);
          henry.addPermission('create@Post', function (err) {
            expect(err).to.not.exist;
            expect(henry.permissions).to.have.length(2);
            next();
          });
        });
      });

      it('should allow settings', function (done) {
        henry.addPermission('read@Post', { a: 'A' }, function (err, obj) {
          expect(err).to.not.exist;
          expect(henry.permissions).to.have.length(1);
          expect(obj.permissions[0].settings).to.exist;
          expect(obj.permissions[0].settings.a).to.equal('A');
          Permission.findOne({ name: 'read@Post' }, function (err, permission) {
            expect(err).to.not.exist;
            expect(henry.permissions[0].permission.equals(permission._id)).to.be.ok;
            done();
          });
        });
      });

      it('should allow settings containing ObjectId', function (done) {
        henry.addPermission('read@Post', { conditions: { _id: henry._id } }, function (err, obj) {
          expect(err).to.not.exist;
          expect(henry).to.have.property('permissions').with.length(1);
          expect(obj.permissions[0]).to.have.property('settings');
          expect(obj.permissions[0].settings).to.have.property('conditions');
          expect(obj.permissions[0].settings.conditions).to.have.property('_id');
          Permission.findOne({ name: 'read@Post' }, function (err, permission) {
            expect(err).to.not.exist;
            expect(henry.permissions[0].permission.equals(permission._id)).to.be.ok;
            User.findById(henry.id, function (err, user) {
              expect(err).to.not.exist;
              expect(user).to.exist;
              expect(user).to.have.property('permissions').with.length(1);
              expect(user.permissions[0]).to.have.property('settings');
              expect(user.permissions[0].settings).to.have.property('conditions');
              expect(user.permissions[0].settings.conditions).to.have.property('_id');

              User.find(user.permissions[0].settings.conditions, function (err, lookupUser) {
                expect(err).to.not.exist;
                expect(lookupUser).to.exist.with.length(1);
                expect(lookupUser[0]._id.equals(henry._id)).to.be.true;
                done();
              });

            });
          });
        });
      });

      it('should allow multiple permissions with same name and different settings', function (done) {
        henry.addPermission('read@Post', { a: 'A' }, function (err, obj) {
          expect(err).to.not.exist;
          expect(henry.permissions).to.have.length(1);
          expect(obj.permissions[0].settings).to.be.like({a: 'A'});
          henry.addPermission('read@Post', function (err, obj) {
            expect(err).to.not.exist;
            expect(henry.permissions).to.have.length(2);
            expect(obj.permissions[1].settings).to.be.like({});
            henry.addPermission('read@Post', { a: 'B' }, function (err, obj) {
              expect(err).to.not.exist;
              expect(henry.permissions).to.have.length(3);
              expect(obj.permissions[2].settings).to.be.like({a: 'B'});
              Permission.find({ name: 'read@Post' }, function (err, permissions) {
                expect(err).to.not.exist;
                expect(permissions).to.exist;
                expect(permissions.length).to.equal(1);
                done();
              });
            });
          });
        });
      });

      it('should reject settingsFactory', function (done) {
        var fn = function (opts) {
          return { a: opts.a }
        };
        henry.addPermission('read@Post', fn, function (err) {
          expect(err).to.exist;
          expect(err.message).equals('Can not add templated permission to user').to.be.ok;
          done();
        });
      });
    });

    describe('removePermission', function () {
      it('should remove a permission from a model', function (next) {
        henry.addPermission('read@Post', function (err) {
          expect(err).to.not.exist;
          henry.removePermission('read@Post', function (err) {
            expect(err).to.not.exist;
            expect(henry.permissions).to.be.empty;
            next();
          });
        });
      });

      it('should remove a permission from a model with the correct decoration', function (done) {
        var pA, pB, p;
        henry.addPermission('read@Post', { a: 'A' }, function (err) {
          expect(err).to.not.exist;
          pA = henry.permissions[0];
          henry.addPermission('read@Post', function (err) {
            expect(err).to.not.exist;
            p = henry.permissions[1];
            henry.addPermission('read@Post', { a: 'B' }, function (err) {
              expect(err).to.not.exist;
              pB = henry.permissions[2];
              henry.removePermission('read@Post', { a: 'B' }, function (err) {
                expect(err).to.not.exist;
                expect(henry.permissions.length).to.equal(2);
                expect(henry.permissions.indexOf(pB)).to.equal(-1);
                henry.removePermission('read@Post', { a: 'A' }, function (err) {
                  expect(err).to.not.exist;
                  expect(henry.permissions.length).to.equal(1);
                  expect(henry.permissions.indexOf(pA)).to.equal(-1);
                  henry.removePermission('read@Post', function (err) {
                    expect(err).to.not.exist;
                    expect(henry.roles.length).to.be.empty;
                    done();
                  });
                });
              });
            });
          });
        });
      });

    });

    describe('can', function () {
      it('should indicate whether a model has a given permission', function (next) {
        henry.addRole('readonly', function (err) {
          expect(err).to.not.exist;
          henry.can('read@Post', function (err, canReadPost) {
            expect(err).to.not.exist;
            expect(canReadPost).to.equal(true);
            henry.can('create@Post', function (err, canCreatePost) {
              expect(err).to.not.exist;
              expect(canCreatePost).to.equal(false);
              next();
            });
          });
        });
      });

      it('should return permission decorations', function (done) {
        henry.addRole('readonly', function (err) {
          expect(err).to.not.exist;
          henry.can('read@Post', function (err, canReadPost, decorations) {
            expect(err).to.not.exist;
            expect(canReadPost).to.equal(true);
            expect(decorations).to.exist;
            expect(decorations.length).to.equal(1);
            expect(decorations[0]).to.be.like({});
            done();
          });
        });
      });

      it('should return distinct permission decorations', function (done) {
        admin.addRole('readonly', function (err) {
          expect(err).to.not.exist;
          henry.addRole('admin', function (err) {
            expect(err).to.not.exist;
            henry.can('read@Post', function (err, canReadPost, permissions) {
              expect(err).to.not.exist;
              expect(canReadPost).to.equal(true);
              expect(permissions).to.exist;
              expect(permissions.length).to.equal(1);
              done();
            });
          });
        });
      });

      it('should return user permissions (not by role)', function (done) {
        henry.addPermission('read@Foo', function (err) {
          expect(err).to.not.exist;
          henry.can('read@Foo', function (err, canRead, decorations) {
            expect(err).to.not.exist;
            expect(canRead).to.equal(true);
            expect(decorations).to.exist;
            expect(decorations.length).to.equal(1);
            expect(decorations[0]).to.be.like({});
            done();
          });
        });
      });

      it('should return multiple decorations when available', function (done) {
        henry.addPermission('read@Foo', function (err) {
          expect(err).to.not.exist;
          henry.addPermission('read@Foo', {a: 'A'}, function (err) {
            expect(err).to.not.exist;
            henry.can('read@Foo', function (err, canRead, decorations) {
              expect(err).to.not.exist;
              expect(canRead).to.equal(true);
              expect(decorations).to.exist;
              expect(decorations.length).to.equal(2);
              expect(decorations[0]).to.be.like({});
              expect(decorations[1]).to.be.like({a: 'A'});
              done();
            });
          });
        });
      });

      it('should return multiple decorations when available in different roles', function (done) {
        henry.addRole('admin', function (err) {
          expect(err).to.not.exist;
          henry.addPermission('read@Post', {a: 'A'}, function (err) {
            expect(err).to.not.exist;
            henry.can('read@Post', function (err, canRead, decorations) {
              expect(err).to.not.exist;
              expect(canRead).to.equal(true);
              expect(decorations).to.exist;
              expect(decorations.length).to.equal(2);
              expect(decorations[0]).to.be.like({a: 'A'});
              expect(decorations[1]).to.be.like({});
              done();
            });
          });
        });
      });

      it('should resolve templated decorations', function (done) {
        henry.addRole('admin', {a: 'A'}, function (err) {
          expect(err).to.not.exist;
          var fnGuest = function (opts) {
            return { b: opts.a };
          };
          admin.addRole('guest', fnGuest, function (err) {
            expect(err).to.not.exist;
            var fnReadFoo = function (opts) {
              return { c: opts.b };
            };
            guest.addPermission('read@Foo', fnReadFoo, function (err) {
              expect(err).to.not.exist;
              henry.can('read@Foo', function (err, canRead, decorations) {
                expect(err).to.not.exist;
                expect(canRead).to.equal(true);
                expect(decorations).to.exist;
                expect(decorations.length).to.equal(1);
                expect(decorations[0]).to.be.like({c: 'A'});
                done();
              });
            });
          });
        });
      });

    });

    describe('canAll', function () {
      it('should indicate whether a model has all of a given set of permissions', function (next) {
        henry.addRole('readonly', function (err) {
          expect(err).to.not.exist;
          henry.canAll([
            'read@Post',
            'read@Comment'
          ], function (err, canRead) {
            expect(err).to.not.exist;
            expect(canRead).to.equal(true);
            henry.canAll([
              'read@Post',
              'create@Post'
            ], function (err, canReadAndCreate) {
              expect(err).to.not.exist;
              expect(canReadAndCreate).to.equal(false);
              next();
            });
          });
        });
      });

      it('should indicate whether a model has all of a given set of permissions even when in different roles', function (next) {
        henry.addRole('readonly', function (err) {
          expect(err).to.not.exist;
          henry.addRole('guest', function (err) {
            expect(err).to.not.exist;
            guest.addPermission('read@Foo', function (err) {
              expect(err).to.not.exist;
              henry.canAll([
                'read@Post',
                'read@Foo'
              ], function (err, canRead) {
                expect(err).to.not.exist;
                expect(canRead).to.equal(true);
                next();
              });
            });
          });
        });
      });

      it('should merge permission decorations', function (next) {
        henry.addRole('readonly', function (err) {
          expect(err).to.not.exist;
          henry.addRole('guest', function (err) {
            expect(err).to.not.exist;
            guest.addPermission('read@Post', {a: 'A'}, function (err) {
              expect(err).to.not.exist;
              henry.canAll([
                'read@Post',
                'read@Comment'
              ], function (err, canRead, permissions) {
                expect(err).to.not.exist;
                expect(canRead).to.equal(true);
                expect(permissions).to.exist;
                expect(permissions['read@Post'].length).to.equal(2);
                expect(permissions['read@Comment'].length).to.equal(1);
                next();
              });
            });
          });
        });
      });

      it('should handle nested roles', function (done) {
        Role.findOne({ name: 'guest'}, function (err, guest) {
          expect(err).to.not.exist;
          guest.addRole('readonly', function (err) {
            expect(err).to.not.exist;
            henry.addRole('guest', function (err) {
              expect(err).to.not.exist;
              henry.canAll([
                'read@Post',
                'read@Comment'
              ], function (err, canRead, permissions) {
                expect(err).to.not.exist;
                expect(canRead).to.equal(true);
                expect(permissions).to.exist;
                expect(permissions['read@Post'].length).to.equal(1);
                expect(permissions['read@Comment'].length).to.equal(1);
                henry.canAll([
                  'read@Post',
                  'create@Post'
                ], function (err, canReadAndCreate, permissions) {
                  expect(err).to.not.exist;
                  expect(canReadAndCreate).to.equal(false);
                  expect(permissions).to.exist;
                  expect(permissions['read@Post'].length).to.equal(1);
                  expect(permissions['create@Post']).to.not.exist;
                  done();
                });
              });
            });
          });
        });
      });
    });

    describe('canAny', function () {
      it('should indicate whether a model has any of a given set of permissions', function (next) {
        henry.addRole('readonly', function (err) {
          expect(err).to.not.exist;
          henry.canAny([
            'read@Post',
            'create@Post'
          ], function (err, canReadOrCreate) {
            expect(err).to.not.exist;
            expect(canReadOrCreate).to.equal(true);
            next();
          });
        });
      });

      it('should find nested role permissions', function (done) {
        Role.findOne({ name: 'guest'}, function (err, guest) {
          expect(err).to.not.exist;
          guest.addRole('readonly', function (err) {
            expect(err).to.not.exist;
            henry.addRole('guest', function (err) {
              expect(err).to.not.exist;
              henry.canAny([
                'read@Post',
                'create@Post'
              ], function (err, canReadOrCreate, permissions) {
                expect(err).to.not.exist;
                expect(canReadOrCreate).to.equal(true);
                expect(permissions).to.exist;
                expect(permissions['read@Post'].length).to.equal(1);
                expect(permissions['create@Post']).to.not.exist;
                done();
              });
            });
          });
        });
      });

      it('should return first encountered permission only', function (done) {
        admin.addRole('readonly', function (err) {
          expect(err).to.not.exist;
          henry.addRole('admin', function (err) {
            expect(err).to.not.exist;
            henry.canAny([
              'create@Post',
              'read@Post',
              'read@Foo'
            ], function (err, canReadOrCreate, permissions) {
              expect(err).to.not.exist;
              expect(canReadOrCreate).to.equal(true);
              expect(permissions).to.exist;
              expect(permissions['create@Post'].length).to.equal(1);
              expect(permissions['read@Post']).not.to.exist;
              expect(permissions['read@Foo']).not.to.exist;
              done();
            });
          });
        });
      });

      it('should return all permissions when explicitly requested', function (done) {
        admin.addRole('readonly', function (err) {
          expect(err).to.not.exist;
          henry.addRole('admin', function (err) {
            expect(err).to.not.exist;
            henry.canAny([
              'create@Post',
              'read@Post',
              'read@Foo'
            ], true, function (err, canReadOrCreate, permissions) {
              expect(err).to.not.exist;
              expect(canReadOrCreate).to.equal(true);
              expect(permissions).to.exist;
              expect(permissions['create@Post'].length).to.equal(1);
              expect(permissions['read@Post'].length).to.equal(1);
              expect(permissions['read@Foo'].length).to.equal(1);
              done();
            });
          });
        });
      });
    });

    describe('direct permissions (no role)', function () {

      beforeEach(function (done) {
        done();

      });

      afterEach(function () {
      });

      after(function () {
      });

      it('', function () {

      });
    });
  });

  describe('acl', function () {
    before(function () {
    });

    beforeEach(function (done) {
      Contact.create([
        { name: 'exc1', club: 'exc' },
        { name: 'exc2', club: 'exc' },
        { name: 'exc3', club: 'exc' },
        { name: 'exc4', club: 'exc' },
        { name: 'des1', club: 'des' },
        { name: 'des2', club: 'des' },
        { name: 'des2', club: 'des' },
        { name: 'dkc1', club: 'dkc' },
        { name: 'dkc2', club: 'dkc' }
      ], function () {
        done();
      })

    });

    afterEach(function () {
    });

    after(function () {
    });

    describe('Model.aclCreate', function () {
      it('should insert presets when none specified', function (done) {
        var permissions = {
          'create@Contact': [
            {
              presets: {
                club: 'exc'
              }
            }
          ]
        };
        Contact.aclCreate(permissions, {name: 'leen'}, function (err, contact) {
          expect(err).to.not.exist;
          expect(contact).to.exist;
          expect(contact).to.have.property('club', 'exc');
          done();
        });
      });

      it('should allow presets when matching', function (done) {
        var permissions = {
          'create@Contact': [
            {
              presets: {
                club: 'exc'
              }
            }
          ]
        };
        Contact.aclCreate(permissions, {name: 'leen', club: 'exc'}, function (err, contact) {
          expect(err).to.not.exist;
          expect(contact).to.exist;
          expect(contact).to.have.property('club', 'exc');
          done();
        });
      });

      it('should allow presets when some set is matching', function (done) {
        var permissions = {
          'create@Contact': [
            {
              presets: {
                club: 'exc'
              }
            },
            {
              presets: {
                club: 'dkc'
              }
            }
          ]
        };
        Contact.aclCreate(permissions, {name: 'leen', club: 'exc'}, function (err, contact) {
          expect(err).to.not.exist;
          expect(contact).to.exist;
          expect(contact).to.have.property('club', 'exc');
          done();
        });
      });

      it('should deny when presets not matching', function (done) {
        var permissions = {
          'create@Contact': [
            {
              presets: {
                club: 'dkc'
              }
            }
          ]
        };
        Contact.aclCreate(permissions, {name: 'leen', club: 'exc'}, function (err) {
          expect(err).to.exist;
          expect(err).to.have.property('message', 'not authorized');
          done();
        });
      });

      it('should deny when all presets not matching', function (done) {
        var permissions = {
          'create@Contact': [
            {
              presets: {
                club: 'dkc'
              }
            },
            {
              presets: {
                club: 'des'
              }
            }
          ]
        };
        Contact.aclCreate(permissions, {name: 'leen', club: 'exc'}, function (err) {
          expect(err).to.exist;
          expect(err).to.have.property('message', 'not authorized');
          done();
        });
      });

      it('should deny all docs when any has presets not matching', function (done) {
        var permissions = {
          'create@Contact': [
            {
              presets: {
                club: 'dkc'
              }
            }
          ]
        };
        var piet = {name: 'piet', club: 'dkc'};
        Contact.aclCreate(permissions, [
          {name: 'leen', club: 'exc'},
          piet
        ], function (err) {
          expect(err).to.exist;
          expect(err).to.have.property('message', 'not authorized');
          Contact.findOne(piet, function (err, piet) {
            expect(err).to.not.exist;
            expect(piet).to.not.exist;
            done();

          });
        });
      });

      describe('sub documents', function () {
        it('should insert presets when none specified', function (done) {
          var permissions = {
            'create@Contact': [
              {
                presets: {
                  club: 'exc',
                  adres: {
                    plaats: 'Delft'
                  }
                }
              }
            ]
          };
          Contact.aclCreate(permissions, {name: 'leen'}, function (err, contact) {
            expect(err).to.not.exist;
            expect(contact).to.exist;
            expect(contact).to.have.property('club', 'exc');
            expect(contact).to.have.property('adres');
            expect(contact.adres).to.have.property('plaats', 'Delft');
            done();
          });
        });

        it('should allow presets when matching', function (done) {
          var permissions = {
            'create@Contact': [
              {
                presets: {
                  club: 'exc',
                  adres: {
                    plaats: 'Delft'
                  }
                }
              }
            ]
          };
          Contact.aclCreate(permissions, {name: 'leen', club: 'exc', adres: { plaats: 'Delft'}}, function (err, contact) {
            expect(err).to.not.exist;
            expect(contact).to.exist;
            expect(contact).to.have.property('club', 'exc');
            expect(contact).to.have.property('adres');
            expect(contact.adres).to.have.property('plaats', 'Delft');
            done();
          });
        });

        it('should allow presets when some set is matching', function (done) {
          var permissions = {
            'create@Contact': [
              {
                presets: {
                  club: 'exc',
                  adres: {
                    plaats: 'Delft'
                  }
                }
              },
              {
                presets: {
                  club: 'dkc',
                  adres: {
                    plaats: 'Delft'
                  }
                }
              }
            ]
          };
          Contact.aclCreate(permissions, {name: 'leen', club: 'exc', adres: { plaats: 'Delft'}}, function (err, contact) {
            expect(err).to.not.exist;
            expect(contact).to.exist;
            expect(contact).to.have.property('club', 'exc');
            expect(contact).to.have.property('adres');
            expect(contact.adres).to.have.property('plaats', 'Delft');
            done();
          });
        });

        it('should deny when presets not matching', function (done) {
          var permissions = {
            'create@Contact': [
              {
                presets: {
                  club: 'exc',
                  adres: {
                    plaats: 'Delft'
                  }
                }
              }
            ]
          };
          Contact.aclCreate(permissions, {name: 'leen', club: 'exc', adres: {plaats: 'Rijswijk'}}, function (err) {
            expect(err).to.exist;
            expect(err).to.have.property('message', 'not authorized');
            done();
          });
        });

        it('should deny when all presets not matching', function (done) {
          var permissions = {
            'create@Contact': [
              {
                presets: {
                  club: 'exc',
                  adres: {
                    plaats: 'Delft'
                  }
                }
              },
              {
                presets: {
                  club: 'exc',
                  adres: {
                    plaats: 'Den Hoorn'
                  }
                }
              }
            ]
          };
          Contact.aclCreate(permissions, {name: 'leen', club: 'exc', adres: { plaats: 'Rijswijk'}}, function (err) {
            expect(err).to.exist;
            expect(err).to.have.property('message', 'not authorized');
            done();
          });
        });

        it('should deny all docs when any has presets not matching', function (done) {
          var permissions = {
            'create@Contact': [
              {
                presets: {
                  club: 'exc',
                  adres: {
                    plaats: 'Delft'
                  }
                }
              }
            ]
          };
          var piet = {name: 'piet', club: 'exc', adres: {plaats: 'Delft'}};
          Contact.aclCreate(permissions, [
            {name: 'leen', club: 'exc', adres: {plaats: 'Rijswijk'} },
            piet
          ], function (err) {
            expect(err).to.exist;
            expect(err).to.have.property('message', 'not authorized');
            Contact.findOne(piet, function (err, piet) {
              expect(err).to.not.exist;
              expect(piet).to.not.exist;
              done();

            });
          });
        });
      });
    });

    describe('query.aclFilter', function () {
      it('should filter query according to permission decoration', function (done) {
        var permissions = {
          'read@Contact': [
            {
              conditions: {
                club: 'exc'
              }
            }
          ]
        };
        Contact.find({}).aclFilter(permissions).exec(function (err, contacts) {
          expect(err).to.not.exist;
          expect(contacts.length).to.equal(4);
          contacts.forEach(function (contact) {
            expect(contact.name).to.match(/^exc/);
          });
          done();
        });
      });

      it('should add to exiting filter', function (done) {
        var permissions = {
          'read@Contact': [
            {
              conditions: {
                club: 'exc'
              }
            }
          ]
        };
        Contact.find({ club: 'dkc' }).aclFilter(permissions).exec(function (err, contacts) {
          expect(err).to.not.exist;
          expect(contacts).to.exist.with.length(0);
          done();
        });
      });

      it('should add to exiting filter (2)', function (done) {
        var permissions = {
          'read@Contact': [
            {
              conditions: {
                club: 'exc'
              }
            }
          ]
        };
        Contact.find({ $and: [
          {club: 'dkc' }
        ] }).aclFilter(permissions).exec(function (err, contacts) {
          expect(err).to.not.exist;
          expect(contacts).to.exist.with.length(0);
          done();
        });
      });

      it('should add to exiting filter (3)', function (done) {
        var permissions = {
          'read@Contact': [
            {
              conditions: {
                club: 'exc'
              }
            }
          ]
        };
        Contact.find().aclFilter(permissions).where({ $and: [
          {club: 'dkc' }
        ] }).exec(function (err, contacts) {
          expect(err).to.not.exist;
          expect(contacts).to.exist.with.length(0);
          done();
        });
      });

      it('should combine decorations', function (done) {
        var permissions = {
          'read@Contact': [
            {
              conditions: {
                club: 'exc'
              }
            },
            {
              conditions: {
                club: 'des'
              }
            }
          ]
        };
        Contact.find({}).aclFilter(permissions).exec(function (err, contacts) {
          expect(err).to.not.exist;
          expect(contacts.length).to.equal(7);
          contacts.forEach(function (contact) {
            expect(contact.name).to.match(/^(exc|des)/);
          });
          done();
        });
      });

      it('should not filter when permission not specified', function (done) {
        var permissions = {};
        Contact.find({}).aclFilter(permissions).exec(function (err, contacts) {
          expect(err).to.not.exist;
          expect(contacts).to.exist.with.length(9);
          done();
        });
      });

      it('should not filter when one of the decorations specifies no conditions', function (done) {
        var permissions = {
          'read@Contact': [
            {
              conditions: {
                club: 'exc'
              }
            },
            {
            }
          ]
        };
        Contact.find({}).aclFilter(permissions).exec(function (err, contacts) {
          expect(err).to.not.exist;
          expect(contacts).to.exist.with.length(9);
          done();
        });
      });

      it('should not filter when one of the decorations specifies empty conditions', function (done) {
        var permissions = {
          'read@Contact': [
            {
              conditions: {
                club: 'exc'
              }
            },
            {
              conditions: {}
            }
          ]
        };
        Contact.find({}).aclFilter(permissions).exec(function (err, contacts) {
          expect(err).to.not.exist;
          expect(contacts).to.exist.with.length(9);
          done();
        });
      });
    });

    describe('Model.aclUpdate', function () {
      it('should succeed if updates within filter conditions', function (done) {
        var permissions = {
          'update@Contact': [
            {
              conditions: {
                club: 'exc',
                'adres.plaats': 'Delft'
              }
            }
          ]
        };

        Contact.create({name: 'leen', club: 'exc', adres: {straat: 'Dorpsweg', plaats: 'Delft'}}, function (err, leen) {
          Contact.aclUpdate(permissions, {_id: leen._id}, {'adres.postcode': '2612VG'}, function (err, cnt) {
            expect(err).to.not.exist;
            expect(cnt).to.equal(1);
            Contact.findById(leen.id, function (err, leen) {
              expect(err).to.not.exist;
              expect(leen).to.exist;
              expect(leen).to.have.property('adres');
              expect(leen.adres).to.have.property('postcode', '2612VG');
              done();
            });
          });
        });
      });

      it('should reject if updates outside filter conditions', function (done) {
        var permissions = {
          'update@Contact': [
            {
              conditions: {
                club: 'exc',
                'adres.plaats': 'Delft'
              }
            }
          ]
        };

        Contact.create({name: 'leen', club: 'exc', adres: {straat: 'Dorpsweg', plaats: 'Den Hoorn'}}, function (err, leen) {
          Contact.aclUpdate(permissions, {_id: leen._id}, {'adres.postcode': '2612VG'}, function (err, cnt) {
            expect(err).to.not.exist;
            expect(cnt).to.equal(0);
            Contact.findById(leen.id, function (err, leen) {
              expect(err).to.not.exist;
              expect(leen).to.exist;
              expect(leen).to.have.property('adres');
              expect(leen.adres).not.to.have.property('postcode');
              done();
            });
          });
        });

      });

      it('should succeed if updates within filter conditions; no callback', function (done) {
        var permissions = {
          'update@Contact': [
            {
              conditions: {
                club: 'exc',
                'adres.plaats': 'Delft'
              }
            }
          ]
        };

        Contact.create({name: 'leen', club: 'exc', adres: {straat: 'Dorpsweg', plaats: 'Delft'}}, function (err, leen) {
          Contact.aclUpdate(permissions, {_id: leen._id}, {'adres.postcode': '2612VG'}).exec(function (err, cnt) {
            expect(err).to.not.exist;
            expect(cnt).to.equal(1);
            Contact.findById(leen.id, function (err, leen) {
              expect(err).to.not.exist;
              expect(leen).to.exist;
              expect(leen).to.have.property('adres');
              expect(leen.adres).to.have.property('postcode', '2612VG');
              done();
            });
          });
        });
      });

      it('should reject if updates outside filter conditions; no callback', function (done) {
        var permissions = {
          'update@Contact': [
            {
              conditions: {
                club: 'exc',
                'adres.plaats': 'Delft'
              }
            }
          ]
        };

        Contact.create({name: 'leen', club: 'exc', adres: {straat: 'Dorpsweg', plaats: 'Den Hoorn'}}, function (err, leen) {
          Contact.aclUpdate(permissions, {_id: leen._id}, {'adres.postcode': '2612VG'}).exec(function (err, cnt) {
            expect(err).to.not.exist;
            expect(cnt).to.equal(0);
            Contact.findById(leen.id, function (err, leen) {
              expect(err).to.not.exist;
              expect(leen).to.exist;
              expect(leen).to.have.property('adres');
              expect(leen.adres).not.to.have.property('postcode');
              done();
            });
          });
        });

      });
    });

    describe('Model.aclRemove', function () {
      it('should succeed removes within filter conditions', function (done) {
        var permissions = {
          'delete@Contact': [
            {
              conditions: {
                club: 'exc',
                'adres.plaats': 'Delft'
              }
            }
          ]
        };

        Contact.create({name: 'leen', club: 'exc', adres: {straat: 'Dorpsweg', plaats: 'Delft'}}, function (err, leen) {
          Contact.aclRemove(permissions, {_id: leen._id}, function (err, cnt) {
            expect(err).to.not.exist;
            expect(cnt).to.equal(1);
            Contact.findById(leen.id, function (err, leen) {
              expect(err).to.not.exist;
              expect(leen).to.not.exist;
              done();
            });
          });
        });
      });

      it('should reject removes outside filter conditions', function (done) {
        var permissions = {
          'delete@Contact': [
            {
              conditions: {
                club: 'exc',
                'adres.plaats': 'Delft'
              }
            }
          ]
        };

        Contact.create({name: 'leen', club: 'exc', adres: {straat: 'Dorpsweg', plaats: 'Den Hoorn'}}, function (err, leen) {
          Contact.aclRemove(permissions, {_id: leen._id}, function (err, cnt) {
            expect(err).to.not.exist;
            expect(cnt).to.equal(0);
            Contact.findById(leen.id, function (err, leen) {
              expect(err).to.not.exist;
              expect(leen).to.exist;
              done();
            });
          });
        });

      });

      it('should succeed removes within filter conditions; no callback', function (done) {
        var permissions = {
          'delete@Contact': [
            {
              conditions: {
                club: 'exc',
                'adres.plaats': 'Delft'
              }
            }
          ]
        };

        Contact.create({name: 'leen', club: 'exc', adres: {straat: 'Dorpsweg', plaats: 'Delft'}}, function (err, leen) {
          Contact.aclRemove(permissions, {_id: leen._id}).exec(function (err, cnt) {
            expect(err).to.not.exist;
            expect(cnt).to.equal(1);
            Contact.findById(leen.id, function (err, leen) {
              expect(err).to.not.exist;
              expect(leen).to.not.exist;
              done();
            });
          });
        });
      });

      it('should reject removes outside filter conditions; no callback', function (done) {
        var permissions = {
          'delete@Contact': [
            {
              conditions: {
                club: 'exc',
                'adres.plaats': 'Delft'
              }
            }
          ]
        };

        Contact.create({name: 'leen', club: 'exc', adres: {straat: 'Dorpsweg', plaats: 'Den Hoorn'}}, function (err, leen) {
          Contact.aclRemove(permissions, {_id: leen._id}).exec(function (err, cnt) {
            expect(err).to.not.exist;
            expect(cnt).to.equal(0);
            Contact.findById(leen.id, function (err, leen) {
              expect(err).to.not.exist;
              expect(leen).to.exist;
              done();
            });
          });
        });

      });
    });

    describe('model.aclSave', function () {
      describe('create', function () {
        it('should insert presets when none specified', function (done) {
          var permissions = {
            'create@Contact': [
              {
                presets: {
                  club: 'exc'
                }
              }
            ]
          };
          new Contact({name: 'leen'}).aclSave(permissions, function (err, contact) {
            expect(err).to.not.exist;
            expect(contact).to.exist;
            expect(contact).to.have.property('club', 'exc');
            done();
          });
        });

        it('should allow presets when matching', function (done) {
          var permissions = {
            'create@Contact': [
              {
                presets: {
                  club: 'exc'
                }
              }
            ]
          };
          new Contact({name: 'leen', club: 'exc'}).aclSave(permissions, function (err, contact) {
            expect(err).to.not.exist;
            expect(contact).to.exist;
            expect(contact).to.have.property('club', 'exc');
            done();
          });
        });

        it('should allow presets when some set is matching', function (done) {
          var permissions = {
            'create@Contact': [
              {
                presets: {
                  club: 'exc'
                }
              },
              {
                presets: {
                  club: 'dkc'
                }
              }
            ]
          };
          new Contact({name: 'leen', club: 'exc'}).aclSave(permissions, function (err, contact) {
            expect(err).to.not.exist;
            expect(contact).to.exist;
            expect(contact).to.have.property('club', 'exc');
            done();
          });
        });

        it('should deny when presets not matching', function (done) {
          var permissions = {
            'create@Contact': [
              {
                presets: {
                  club: 'dkc'
                }
              }
            ]
          };
          new Contact({name: 'leen', club: 'exc'}).aclSave(permissions, function (err) {
            expect(err).to.exist;
            expect(err).to.have.property('message', 'not authorized');
            done();
          });
        });

        it('should deny when all presets not matching', function (done) {
          var permissions = {
            'create@Contact': [
              {
                presets: {
                  club: 'dkc'
                }
              },
              {
                presets: {
                  club: 'des'
                }
              }
            ]
          };
          new Contact({name: 'leen', club: 'exc'}).aclSave(permissions, function (err) {
            expect(err).to.exist;
            expect(err).to.have.property('message', 'not authorized');
            done();
          });
        });

        describe('sub documents', function () {
          it('should insert presets when none specified', function (done) {
            var permissions = {
              'create@Contact': [
                {
                  presets: {
                    club: 'exc',
                    adres: { plaats: 'Delft'}
                  }
                }
              ]
            };
            new Contact({name: 'leen'}).aclSave(permissions, function (err, contact) {
              expect(err).to.not.exist;
              expect(contact).to.exist;
              expect(contact).to.have.property('club', 'exc');
              expect(contact).to.have.property('adres');
              expect(contact.adres).to.have.property('plaats', 'Delft');
              done();
            });
          });

          it('should allow presets when matching', function (done) {
            var permissions = {
              'create@Contact': [
                {
                  presets: {
                    club: 'exc',
                    adres: { plaats: 'Delft'}
                  }
                }
              ]
            };
            new Contact({name: 'leen', club: 'exc', adres: {plaats: 'Delft'}}).aclSave(permissions, function (err, contact) {
              expect(err).to.not.exist;
              expect(contact).to.exist;
              expect(contact).to.have.property('club', 'exc');
              expect(contact).to.have.property('adres');
              expect(contact.adres).to.have.property('plaats', 'Delft');
              done();
            });
          });

          it('should allow presets when some set is matching', function (done) {
            var permissions = {
              'create@Contact': [
                {
                  presets: {
                    club: 'exc',
                    adres: { plaats: 'Delft'}
                  }
                },
                {
                  presets: {
                    club: 'exc',
                    adres: { plaats: 'Den Hoorn'}
                  }
                }
              ]
            };
            new Contact({name: 'leen', club: 'exc', adres: {plaats: 'Delft'}}).aclSave(permissions, function (err, contact) {
              expect(err).to.not.exist;
              expect(contact).to.exist;
              expect(contact).to.have.property('club', 'exc');
              expect(contact).to.have.property('adres');
              expect(contact.adres).to.have.property('plaats', 'Delft');
              done();
            });
          });

          it('should deny when presets not matching', function (done) {
            var permissions = {
              'create@Contact': [
                {
                  presets: {
                    club: 'exc',
                    adres: { plaats: 'Delft'}
                  }
                }
              ]
            };
            new Contact({name: 'leen', club: 'exc', adres: {plaats: 'Rijswijk'}}).aclSave(permissions, function (err) {
              expect(err).to.exist;
              expect(err).to.have.property('message', 'not authorized');
              done();
            });
          });

          it('should deny when all presets not matching', function (done) {
            var permissions = {
              'create@Contact': [
                {
                  presets: {
                    club: 'exc',
                    adres: { plaats: 'Delft'}
                  }
                },
                {
                  presets: {
                    club: 'exc',
                    adres: { plaats: 'Den Hoorn'}
                  }
                }
              ]
            };
            new Contact({name: 'leen', club: 'exc', adres: {plaats: 'Rijswijk'}}).aclSave(permissions, function (err) {
              expect(err).to.exist;
              expect(err).to.have.property('message', 'not authorized');
              done();
            });
          });
        });
      });

      describe('update', function () {
        it('should succeed if updates within filter conditions', function (done) {
          var permissions = {
            'update@Contact': [
              {
                conditions: {
                  club: 'exc',
                  'adres.plaats': 'Delft'
                }
              }
            ]
          };

          Contact.create({name: 'leen', club: 'exc', adres: {straat: 'Dorpsweg', plaats: 'Delft'}}, function (err, leen) {
            leen.adres.postcode = '2612VG';
            leen.aclSave(permissions, function (err, leen) {
              expect(err).to.not.exist;
              expect(leen).to.exist;
              expect(leen).to.have.property('adres');
              expect(leen.adres).to.have.property('postcode', '2612VG');
              Contact.findById(leen.id, function (err, leen) {
                expect(err).to.not.exist;
                expect(leen).to.exist;
                expect(leen).to.have.property('adres');
                expect(leen.adres).to.have.property('postcode', '2612VG');
                done();
              });
            });
          });
        });

        it('should reject if updates outside filter conditions', function (done) {
          var permissions = {
            'update@Contact': [
              {
                conditions: {
                  club: 'exc',
                  'adres.plaats': 'Delft'
                }
              }
            ]
          };

          Contact.create({name: 'leen', club: 'exc', adres: {straat: 'Dorpsweg', plaats: 'Den Hoorn'}}, function (err, leen) {
            leen.adres.postcode = '2612VG';
            leen.aclSave(permissions, function (err) {
              expect(err).to.exist;
              expect(err).to.have.property('message', 'not authorized');
              Contact.findById(leen.id, function (err, leen) {
                expect(err).to.not.exist;
                expect(leen).to.exist;
                expect(leen).to.have.property('adres');
                expect(leen.adres).not.to.have.property('postcode');
                done();
              });
            });
          });

        });
      });
    });

    describe('model.aclRemove', function () {
      it('should succeed remove within filter conditions', function (done) {
        var permissions = {
          'delete@Contact': [
            {
              conditions: {
                club: 'exc',
                'adres.plaats': 'Delft'
              }
            }
          ]
        };

        Contact.create({name: 'leen', club: 'exc', adres: {straat: 'Dorpsweg', plaats: 'Delft'}}, function (err, leen) {
          leen.aclRemove(permissions, function (err, leen) {
            expect(err).to.not.exist;
            expect(leen).to.exist;
            expect(leen).to.have.property('adres');
            Contact.findById(leen.id, function (err, leen) {
              expect(err).to.not.exist;
              expect(leen).to.not.exist;
              done();
            });
          });
        });
      });

      it('should reject remove outside filter conditions', function (done) {
        var permissions = {
          'delete@Contact': [
            {
              conditions: {
                club: 'exc',
                'adres.plaats': 'Delft'
              }
            }
          ]
        };

        Contact.create({name: 'leen', club: 'exc', adres: {straat: 'Dorpsweg', plaats: 'Den Hoorn'}}, function (err, leen) {
          leen.aclRemove(permissions, function (err) {
            expect(err).to.exist;
            expect(err).to.have.property('message', 'not authorized');
            Contact.findById(leen.id, function (err, leen) {
              expect(err).to.not.exist;
              expect(leen).to.exist;
              expect(leen).to.have.property('adres');
              expect(leen.adres).not.to.have.property('postcode');
              done();
            });
          });
        });

      });
    });

  });
});


