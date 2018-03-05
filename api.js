"use strict"

const AWS = require('aws-sdk');
const Joi = require('joi')

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
        done(err);
      } else {
        done();
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
      function(err, data) {
        if (err) { callback(err, null) }
        else {
          if (data && data.Item) {
            callback(null, data.Item)
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

    const docClient = new AWS.DynamoDB.DocumentClient();

    docClient.put(
      {
        TableName: "USERS",
        Item: user
      }, 
      (err, data) => {
      if (err) {
        done(err, null)
      } else {

        done(null, this._bindUtilsToUser(user));  
      }
    });

    return this;
  },

  getPolicy(role, callback) {
    callback(null,{'profile': true});
  },

  _bindUtilsToUser(user) {
    user.verifyPassword = function(password) {
      return user.login.password === password;
    }
    return user
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