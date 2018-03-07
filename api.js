"use strict"

const AWS = require('aws-sdk');
const Joi = require('joi')

const crypto = require('crypto')

let dynamodb = null
const userDB = {}

const Users = {
  TableName : "USERS",
  KeySchema: [       
      { AttributeName: "username", KeyType: "HASH"},  //Partition key
      { AttributeName: "role", KeyType: "RANGE" }  //Sort key
  ],
  AttributeDefinitions: [       
      { AttributeName: "username", AttributeType: "S" },
      { AttributeName: "role", AttributeType: "S" }
  ],
  ProvisionedThroughput: {       
      ReadCapacityUnits: 10, 
      WriteCapacityUnits: 10
  }
};


const db = {

  _ready: false,

  createTable(done) {
    if (!this._ready) {
      console.error("DynamoDB is not ready yet")
      return this;
    }

    dynamodb.createTable(Users, function(err, data) {
      if (err) {
        done && done(err);
      } else {
        done && done();
      }
    });

    return this;
  },

  findUser({ username = null, role = null }, callback) {

    if (!username || !role ) {
      callback({error: 'must specify username and role'})
      return
    }

    if (username.length === 0 || role.length === 0) {
      callback({error: 'username and role must no empty'})
      return
    }

    const docClient = new AWS.DynamoDB.DocumentClient();
    docClient.get(
      { 
        TableName: "USERS", 
        Key: {
          "username": username,
          "role": role
        }
      },
      (err, data) => {
        if (err) { callback({error:err}, null) }
        else {
          if (data && data.Item) {
            callback(null, this._bindUtilsToUser.call(this, data.Item))
          } else {
            callback(null, null)
          }
        }
        
      }
    );
  },

  createUser(user, done) {
    if (!this._ready) {
      done({error: 'dynamo-db is not ready yet'}, null);
      return this;
    }

    const now = new Date();
    user.createdAt = now.getTime();

    user.login.password = this._hashPassword(user.login.password);

    const docClient = new AWS.DynamoDB.DocumentClient();

    docClient.put(
      {
        TableName: "USERS",
        Item: user
      }, 
      (err, data) => {
      if (err) {
        done && done(err, null)
      } else {

        done && done(null, this._bindUtilsToUser.call(this, user));  
      }
    });

    return this;
  },

  deleteUser({username, role}) {
    if (!this._ready) {
      done({error: 'dynamo-db is not ready yet'}, null);
      return this;
    }

    const docClient = new AWS.DynamoDB.DocumentClient();

    docClient.delete(
      {
        TableName: "USERS",
        Key: {username, role}
      }, 
      (err, data) => {
      if (err) {
        done(err, null)
      } else {

        done(null, data);  
      }
    });

    return this;

  },

  getPolicy(role, callback) {
    callback(null,{'profile': true});
  },

  _bindUtilsToUser(user) {
    user.verifyPassword = (password) => {
      return user.login.password === this._hashPassword(password);
    }
    return user
  },

  _hashPassword(password) {
    const hash = crypto.createHash('sha256');
    const head = process.env.PWD_PREFIX;
    const tail = process.env.PWD_SUFFIX;
    hash.update(`${head}${password}${tail}`);
    return hash.digest('hex');
  }

}

function DynamoDB({ region = 'us-west-2', endpoint = 'http://localhost:8000' }, onReady) {
 
  AWS.config.update({ region, endpoint });
 
  dynamodb = new AWS.DynamoDB();

  if (onReady) {
    dynamodb.listTables(function (err, data) {
      if (err) {
        console.log("Error when checking DynamoDB status")
        db._ready = false;
        onReady(err);
      } else {
        db._ready = true;
        onReady();
      }
    });
  } else {
    db._ready = true;
  }

  return db;

}

module.exports = DynamoDB;