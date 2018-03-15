"use strict"

const AWS = require('aws-sdk');
const Joi = require('joi')

const crypto = require('crypto')

let dynamodb = null
const userDB = {}

const Users = {
  TableName : "USERS",
  KeySchema: [       
    { AttributeName: "uid", KeyType: "HASH" }
  ],
  AttributeDefinitions: [       
    { AttributeName: "uid", AttributeType: "S" },
    { AttributeName: "username", AttributeType: "S" }
  ],
  GlobalSecondaryIndexes: [{
    IndexName: "LOGIN",
    KeySchema: [
      { AttributeName: "username", KeyType: "HASH"},     
    ],
    Projection: {
        ProjectionType: "ALL"
    },
    ProvisionedThroughput: {
        ReadCapacityUnits: 1,
        WriteCapacityUnits: 1
    }
  }],
  ProvisionedThroughput: {       
      ReadCapacityUnits: 1, 
      WriteCapacityUnits: 1
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

  dropTable(done) {
    if (!this._ready) {
      console.error("DynamoDB is not ready yet")
      return this;
    }
    dynamodb.deleteTable({ TableName: "USERS" }, done)
  },

  queryUser({ username = null, uid = null }, done) {

    if (!username  && !uid ) {
      done({error: 'must specify username or uid'}, null)
      return
    }

    if (username.length === 0 && uid.length === 0) {
      done({error: 'username and uid are empty'})
      return
    }

    const params = uid && uid.length > 0 ?
      { 
        TableName: "USERS", 
        KeyConditionExpression: `uid = :uid`,
        ExpressionAttributeValues: {
          ':uid' : uid
        } 
      }
      :
      { 
        TableName: "USERS", 
        IndexName: "LOGIN", 
        KeyConditionExpression: `username = :username`,
        ExpressionAttributeValues: {
          ':username' : username
        }  
      }

    const docClient = new AWS.DynamoDB.DocumentClient();
    docClient.query(params,
      (err, data) => {
        if (err) { done({error:err}, null) }
        else {
          if (data && data.Items && data.Items.length > 0) {
            done(null, this._bindUtilsToUser.call(this, data.Items[0]))
          } else {
            done(null, null)
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

  deleteUser(uid) {
    if (!this._ready) {
      done({error: 'dynamo-db is not ready yet'}, null);
      return this;
    }

    const docClient = new AWS.DynamoDB.DocumentClient();

    docClient.delete(
      {
        TableName: "USERS",
        Key: { uid }
      }, 
      (err, data) => {
      if (err) {
        done(err)
      } else {
        done(null);  
      }
    });

    return this;

  },

  update(uid, props, done) {
    if (!this._ready) {
      done({error: 'dynamo-db is not ready yet'}, null);
      return this;
    }

    if (!uid) {
      done({error: 'need to specify uid'}, null);
      return this;
    }


    if (props) {
      if (props.login) {
        this._updatePassword(uid, props, done);
        return this;
      } else {
        this._updateUserProps(uid, props, done);
      }   
    } else {
      done({error: 'need specify changes'}, null);
    }

  },

  _updateUserProps(uid, props, done) {

    const docClient = new AWS.DynamoDB.DocumentClient();
    let exp  = 'set';
    const val = {};
    let i = 1;

    if (props.uid) {
      uid = props.uid;
      delete props.uid;
    }

    for (let name in props) {
      if (typeof props[name] === 'object') {
        for (let item in props[name]) {
          const v = `:c${i}`;
          exp += ` ${name}.${item} = ${v},`;
          val[v] = props[name][item];
          i++;
        }
      } else {
        const v = `:c${i}`;
        exp += ` ${name} = :c${i},`;
        val[v] = props[name];
        i++
      }
    }

    exp = exp.replace(/,$/,'')

    docClient.update(
      {
        TableName: 'USERS',
        Key: { uid },
        UpdateExpression: exp,
        ExpressionAttributeValues: val,
        ReturnValues:"UPDATED_NEW"
      },
      done
    )

  },

  _updatePassword(uid, {login}, done) {

    const docClient = new AWS.DynamoDB.DocumentClient();

    const exp  = 'set login.password = :p';
    const val = { ':p': this._hashPassword(login.password)};

    docClient.update(
      {
        TableName: 'USERS',
        Key: { uid },
        UpdateExpression: exp,
        ExpressionAttributeValues: val,
        ReturnValues:"UPDATED_NEW"
      },
      done
    )

  },

  getPolicy(roles, callback) {
    const policies = {}
    roles.forEach( (role) => {
      if (role === 'admin') {
        policies.super = true;
      } else {
        policies.account = true;
      }
    })
    callback(null, policies)
  },

  _bindUtilsToUser(user) {

    user.verifyPassword = (password) => {
      return user.login.password === this._hashPassword(password);
    }

    user.updatePassword = ({login}, done) => {

      if (!this._ready) {
        done({error: 'dynamo-db is not ready yet'}, null);
        return this;
      }
  
      this._updatePassword(user.uid, {login}, done);

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