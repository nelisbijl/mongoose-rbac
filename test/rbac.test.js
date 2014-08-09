/* global describe,it,before,beforeEach,afterEach */

var expect = require('chai').expect
  , rbac = require('../')
  , common = require('./common')
  , Role = rbac.Role
  , User = common.User;

before(function (next) {
  common.setup('mongodb://localhost/rbac_test', next);
});

describe('roles and permissions:', function () {
  var henry, admin;

  beforeEach(function (next) {
    common.loadFixtures(function (err) {
      if (err) return next(err);
      User.findOne({ username: 'henry' }).populate('roles').exec(function (err, user) {
        if (err) return next(err);
        henry = user;
        Role.findOne({name: 'admin'}, function (err, role) {
          admin = role;
          next();
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
      })

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
              henry.hasRole('readonly', true, function (err, hasReadOnlyRole) { // only direct roles
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

      it('should return permissions', function (done) {
        henry.addRole('readonly', function (err) {
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

      it('should return distinct permissions', function (done) {
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
                  expect(permissions['create@Post'].length).to.equal(0);
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
                expect(permissions['create@Post'].length).to.equal(0);
                done();
              });
            });
          });
        });
      });

      it('should return permissions only for the first encountered role', function (done) {
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
              expect(permissions['create@Post'].length).to.equal(0);
              expect(permissions['read@Post'].length).to.equal(1);
              expect(permissions['read@Foo'].length).to.equal(1);
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
      var guest;

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

});


