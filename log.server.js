/* 
Hello! Welcome to the Node.js log server script!

IMPORTANT:
As all the other code written by the ac.gt project, its best not to edit this code directly, but to
change the running options with command line parameters. Availble parameters are:
  --webPort (the port your server will run on. Default is 8080. If you run the script as root user you may use 80)
  --neoPort (the port your Neo4j server is listening on. Default is 7474, which typically never needs to be changed)
  --neoUser (the username of the user you want to connect to Neo4j. Default is 'neo4j', the root user)
  --neoPass (the password of the user you want to connect to Neo4j. Default is also 'neo4j')
  --neoHost (the hostname that your Neo4j server is running on. Default is localhost)
  --rootDir (the local directory which will act as the webservers root directory. Webserver is chrooted to this path,
         i.e. if the rootDir is "/var/www/htdocs/log", clients cannot see anything in /var/www/htdocs/, but 
         would be able to see /var/www/htdocs/log/woops/thing.jpg. Default is './www/' )
  -- userDB (the full path to the user SQL database, which stores the usernames/passwords/configs/etc. Default is
         './database/users.sqlite')

INSTALLATION:
Installing a log logging/authentication server is easy once you've got Neo4j set up. Setting Neo4j up
however is not always that easy. There are many optimization settings, the set up is liable to change since
its under rapid development right now, and security is pretty much non-existant. Atleast for the Community version.
Anything I write here might not be true in a week from now, so i'm very hesitant to write instructions, 
particulary as Neo4j gives clients the ability to execute scripts server-side by default! So when it comes to
installing Neo, you'll have to read the latest docs on what to do. Personally I always set it up behind an
Apache or Nginx reverse proxy to limit the directories external IPs can GET/POST to, but again, I cant help
you here because those paths could change and what I thought was secure will later turn out to be a lawsuit :(

But once you have it running, its really easy to do the rest. 
First navigate to the directory you want all your data in, and do the following:

mkdir ./database
sqlite3 ./database/users.sqlite
CREATE TABLE users ('account' TEXT collate nocase,'email' TEXT collate nocase,'hash' TEXT,'salt' TEXT,'apikey' TEXT,'failed' INT,'last' datetime,'config' TEXT);
.exit
mkdir ./www
cd ./www
for url in $(curl http://log.bio/all); do curl --create-dirs -o $url http://log.bio/$url; done
cd ..
npm install --user neo4j async crypto sqlite3 express request compression pm2
pm2 start log.js


DESCRIPTION:
This script has two main functions: 
  - To host a number of static files (.html/.css/.js) that make up the website from the rootDir directory.
  - To offer a number of special URLs that users can use to interact with the Neo4j and the SQL databases.

To see all the static files you (or the main log.bio site) are hosting, visit http://server.com/all
This can provide some peace of mind that your not serving things you didnt mean to.

SECURITY:
As a firm opponent of security through obscurity, the code below is what we actually run on log.bio
That means that if you find a bug below, it will exist in our server too. So please please please, if
you see anything thats wrong, send us a mail letting us know so we can patch it up. People who found bugs
will be credited right here in the server code forever more :)

*/

var logVer = 0.1;
var webPort = 3002;
var neoPort = 7474; 
var neoUser = 'neo4j';
var neoPass = 'neo4j';
var neoHost = 'localhost';
var rootDir = '/www/log.bio/';
var userDB = '/databases/users.log.bio';

var dns = require('dns');
var http = require('http');
var walk = require('walk');
var neo4j = require('neo4j');
var https = require('https');
var async = require('async');
var crypto = require('crypto');
var sqlite3 = require('sqlite3').verbose();
var express = require('express');
var request = require('request');
var compress = require('compression');

var restapi = express();
var db = new sqlite3.Database(userDB); 

var graphDB = new neo4j.GraphDatabase('http://'+neoUser+':'+neoPass+'@'+neoHost+':'+String(neoPort));
var sentinel = {};
var blacklist = [];
setInterval(function(sentinel){sentinel={}},  600000 ) // Reset counts every 10 minutes
setInterval(function(sentinel){blacklist=[]}, 6000000) // Unblock everyone every 100 minutes

// When to blacklist naughty IPs:
yoSentinel = function(type,req) {
  var IP = req.req.headers['x-real-ip'];
  if (IP in sentinel) {
    if (type in sentinel[IP]) {
      count = ++sentinel[IP][type];
           if (type == 'log' && count > 100)        { guilty(req) }
      else if (type == 'API' && count > 100)        { guilty(req) }
      else if (type == 'pass' && count > 100)       { guilty(req) }
      else if (type == 'setConfig' && count > 50)   { guilty(req) }
      else if (type == 'register' && count > 50)    { guilty(req) }
      else if (type == 'newAPIKEY' && count > 20)   { guilty(req) }
      else if (type == 'newPassword' && count > 10) { guilty(req) }
      else if (type == 'newRegister' && count > 5)  { guilty(req) }
      else { console.log(type,count); }
    } else { sentinel[IP][type] = 1; }
  } else {
    sentinel[IP] = {};
    sentinel[IP][type] = 1;
  }
};

// What to do when IP blacklisted:
guilty = function(req) {
  var IP = req.req.headers['x-real-ip'];
  dns.reverse(IP, function(err, domains) {
    if(err) { DNS = err } else { DNS = domains }
    console.log(IP,DNS);
    // Currently does nothing.
    // We tested a bunch of npm modules related to blocking IPs, but all were
    // very very slow. If someone can send 1000 requests per second to your application
    // to decide if it should block or not, they have already won. 
    // The block HAS to be implimented at the network level, presumably by the kernel using
    // iptables or ipfw. We will probably make an npm module to do exactly this, and require
    // it in this project in the future.
  });
}

// Function to parse user-submitted JSON
parseJSON = function(req,res,callback) {
  var jsonString = '';
  req.on('data', function (data) { jsonString += data; });
  req.on('end', function () {
    try { callback(JSON.parse(jsonString)); }
    catch (e) { res.json({'success':false,'reason':'I only listen to JSON and J-POP.'}); }
  });
}

// Authenticates users via API key (for adding data to graph)
loginAPI = function(apikey,res,callback) {
    account = apikey.split(':')[0]
    apikey = apikey.split(':')[1]
    db.get('SELECT * FROM users WHERE account=? AND apikey=?;', [account,apikey], function(err,row){
      if (!err && row != undefined) { callback(row); } else { yoSentinel('API',res); callback(false); }
    });
}

// Authenticates users via password hash (for editing user config, changing account information, etc)
loginPass = function(account,password,res,callback) {
    db.get('SELECT * FROM users WHERE account=?;', [account] , function(err,row){
      if (!err && row != undefined) {
        var passHash = crypto.createHash('md5').update(password + row.salt).digest('hex');
        if (passHash == row.hash) { callback(row); } else { callback(false); }
      } else {
        yoSentinel('passFailed',res); 
        callback(null);
      }
    });
}

// Takes account and apikey, and returns the user's config.
restapi.post('/config', function(req, res){
  parseJSON(req,res,function(postData) {
    if ('apikey' in postData) {
      loginAPI(postData.apikey,res, function(result) {
        if (result) {
            res.json({
              success: true,
              logVersion: logVer,
              config: result.config
            });
        } else { res.json({ success:false, reason:'Username or API key invalid.' }); }
      });
    } else {
      res.json({success:false,reason:'UNACCEPTABLEEEE'});
    }
  });
});

// Takes account, password hash and WEBSITE FORMATTED config, and updates the user config
restapi.post('/setConfig', function(req, res){
  parseJSON(req,res,function(postData) {
    if ('account' in postData && 'password' in postData && 'config' in postData) {
      loginPass(postData.account,postData.password,res, function(result) {
        if (result == false || result == null) { res.json({ success:false, reason:'Account name or password are wrong.' }); }
	else {
          var validOptions = ['username','userAs','hostname','verbose','screen','silent',
                    'mail','mailTo','mailServer','call','callTo','text','textTo',
                    'twilio','log','ask','logServer','md5','shortcutAt','blocksize',
                    'maxBackup','maxEvents','debug'];
          var newConfig = {apikey:result.account + ':' + result.apikey};
          for (var i = 0; i < validOptions.length; i++) {
            if (validOptions[i] in postData.config) {
              if (postData.config[validOptions[i]] == 'default') { continue }
              else if (postData.config[validOptions[i]] == 'true' || postData.config[validOptions[i]] == true ) { 
                newConfig[validOptions[i]] = true;
              }
              else if (postData.config[validOptions[i]] == 'false' || postData.config[validOptions[i]] == false) {
                newConfig[validOptions[i]] = false;
              }
              else if (postData.config[validOptions[i]] == 'runtime') { 
                newConfig[validOptions[i]] = null;
              }
              else if (postData.config[validOptions[i]] == 'static') {
                if (validOptions[i]+'Static' in postData.config) {
                  if (postData.config[validOptions[i]+'Static'] == '') { continue }
                  if (!isNaN(postData.config[validOptions[i]+'Static']) && validOptions[i] != 'mailTo' && validOptions[i] != 'callTo') {
                    newConfig[validOptions[i]] = Number(postData.config[validOptions[i]+'Static']);
                  } else {
                    newConfig[validOptions[i]] = postData.config[validOptions[i]+'Static'];
                  }
                } else {
                  res.json({ 
                    success:false, 
                    reason:'You tried to set option '+validOptions[i]+' but no value was provided?!' 
                  });
                }
              } else {
                res.json({ success:false, reason:'I couldnt parse your request for value ' + validOptions[i] });
              }
            }
          }
          //yoSentinel('setConfig',res);
          var stmt = db.prepare("UPDATE users SET config=? WHERE account=?");
          stmt.run(JSON.stringify(newConfig), result.account);
          stmt.finalize();
          res.json({ success:true, data:newConfig });
        }
      });
    } else {
      res.json({ success:false, reason:'UNACCEPTABLEEEE'});
    }
  });
});


// Takes account, password hash, and event ID, and a note - sets the note on the event
restapi.post('/updateNote', function(req, res){
  parseJSON(req,res,function(postData) {
    if ('account' in postData && 'password' in postData && 'id' in postData && 'note' in postData) {
      loginPass(postData.account,postData.password,res, function(result) {
        if (result == false || result == null) { res.json({ success:false, reason:'Account name or password are wrong.' }); }
	else { 
          yoSentinel('updateNote',res);
          note = postData.note.trim();
	  if (note == '' || note == undefined) {
            graphDB.cypher({
              query: "\
                MATCH (e:event {id:{id}, account:{account}}) \
                SET e.note = NULL \
              ",
              params: {
                id: postData.id,
                account: postData.account,
              }
            }, function (err, results) {
              if (!err) { res.json({ success:true }); }
              else { res.json({ success:false, reason:err }); }
            });
          } else {
            graphDB.cypher({
              query: "\
                MATCH (e:event {id:{id}, account:{account}}) \
                SET e.note = {note} \
              ",
              params: {
                id: postData.id,
                account: postData.account,
                note: note
              }
            }, function (err, results) {
              if (!err) { res.json({ success:true }); }
              else { res.json({ success:false, reason:err }); }
            });
          }
        }
      });
    } else {
      //res.json({ success:false, reason:'UNACCEPTABLEEEE'});
      res.json({ success:false, reason:postData});
    }
  });
});


// takes account, password hash, and a new password hash, and updates the database accordingly.
restapi.post('/newPassword', function(req, res){
  parseJSON(req,res,function(postData) {
    if ('account' in postData && 'password' in postData && 'newPassword' in postData) {
      loginPass(postData.account,postData.password,res, function(result) {
        if (result == false || result == null) { res.json({ 'success':false,'reason':'Account name or password are wrong.' }); }
	else {
          yoSentinel('newPassword',res);
          var newHash = crypto.createHash('md5').update(postData.newPassword + result.salt).digest('hex');
          var stmt = db.prepare("UPDATE users SET hash=? WHERE account=?");
          stmt.run(newHash,postData.account);
          stmt.finalize();
          res.json({ 'success':true });
        }
      });
    } else {
      res.json({'success':false,'reason':'UNACCEPTABLEEEE'});
    }
  });
});

// takes account and password hash, and generates a new API key.
restapi.post('/newAPIKEY', function(req, res){
  parseJSON(req,res,function(postData) {
    if ('account' in postData && 'password' in postData) {
      loginPass(postData.account,postData.password,res, function(result) {
        if (result == false || result == null) { res.json({ success:false,'reason':'Account name or apikey are wrong.' }); }
	else {
          yoSentinel('newAPIKEY',res);
          var stmt = db.prepare("UPDATE users SET apikey=?,config=? WHERE account=?");
          var apikey = crypto.createHash('md5').update(Math.random().toString(36)).digest('hex');
          var newConfig = JSON.parse(result.config);
          newConfig.apikey = result.account + ':' + apikey;
          stmt.run(apikey,JSON.stringify(newConfig),postData.account);
          stmt.finalize();
          res.json({ success:true, apikey:apikey });
        }
      });
    } else {
      res.json({success:false,reason:'UNACCEPTABLEEEE'});
    }
  });
});

// takes account and password hash, and generates a new API key.
restapi.get('/all', function(req, res){
  var walker  = walk.walk(rootDir, { followLinks: false });
  var files = '';
  walker.on('file', function(root, stat, next) {
    root = root.split('//');
    if (root.length == 2) { relPath = '/'+root[1]+'/'; } else { relPath = '/'; }
    files = files + relPath + stat.name + '\n';
    next();
  });
  walker.on('end', function() {
    res.send(files);
  });
});

// takes account, apikey and log data, and adds the data to the database.
restapi.post('/log', function(req, res){
  parseJSON(req,res,function(postData) {
    if ('apikey' in postData && 'resources' in postData && 'event' in postData) {
      loginAPI(postData.apikey,res, function(result) {
        if (result) {
          yoSentinel('log',res);
          async.series([
            function(callback){
              // FIRST WE ADD THE RESOURCES
              async.each(postData.resources, function(resource, backcall){
                graphDB.cypher({
                  query: "\
                    MERGE (r:resource {md5:{md5},pHash:{pHash},filesize:{filesize}}) \
                    ON CREATE SET r.addedBy = {addedBy} \
                    FOREACH(x in CASE WHEN {name} in r.names THEN [] ELSE [1] END | \
                       SET r.names = coalesce(r.names,[]) + {name} \
                    )",
                  params: {
                    md5: resource.md5,
                    pHash: resource.pHash,
                    filesize: resource.Filesize,
                    addedBy: postData.apikey.split(':')[0],
                    name: resource.LastFileName
                  }
                }, function (err, results) {
                  if (err) { console.log(err) };
                  backcall(err,'Resources Added');
                });
              }, function(err){
                callback(err,'Resources Added');
              });
            },
            function(callback){
              // THEN WE ADD THE EVENT
              graphDB.cypher({
                query: '\
                  CREATE (e:event { account:{account},id:{id},startTime:{startTime},duration:{duration}, \
                      user:{user},runAs:{runAs},runOn:{runOn},command:{command},output:{output},errors:{errors} })',
                params: {
                  account            : postData.apikey.split(':')[0],
                  id                 : postData.event.ID,
                  startTime          : postData.event.startTime,
                  duration           : postData.event.Duration,
                  user               : postData.event.User,
                  runAs              : postData.event.runAs,
                  runOn              : postData.event.runOn,
                  command            : postData.event.Command,
                  output             : postData.event.Output,
                  errors             : postData.event.Errors
                }
              }, function (err, results) {
                  if (err) { console.log(err) };
                  callback(err,'Event Added');
              });
            }
          ],
          function(err, results) {
            // AND FINALLY THE RELATIONSHIPS (ASYNC)
            if (postData.event.Used.length != 0) {
              graphDB.cypher({
                query: "MATCH (e:event {id:{id}}),(r:resource) \
                  WHERE r.md5 IN {used} \
                  FOREACH(idx in RANGE(0,SIZE({fileMD5})-1) | \
                    FOREACH( filePath IN CASE WHEN r.md5 = {fileMD5}[idx] THEN [{filePaths}[idx]] ELSE [] END | \
                      CREATE UNIQUE (r)-[:USED_BY {filePath:filePath}]->(e) \
                    ) \
                  )",
                params: {
                  id        : postData.event.ID,
                  used      : postData.event.Used,
                  fileMD5   : postData.event.filePaths[0],
                  filePaths : postData.event.filePaths[1]
                }
              }, function (err, results) {
                if (err) { console.log(err) } else { console.log('Added USED relationships')} 
              });
            }
            if (postData.event.MaybeUsed.length != 0) {
              graphDB.cypher({
                query: "MATCH (e:event{id:{id}}),(r:resource) \
                  WHERE r.md5 IN {maybeUsed} \
                  FOREACH(idx in RANGE(0,SIZE({fileMD5})-1) | \
                    FOREACH( filePath IN CASE WHEN r.md5 = {fileMD5}[idx] THEN [{filePaths}[idx]] ELSE [] END | \
                      CREATE UNIQUE (r)-[:MAYBE_USED_BY {filePath:filePath}]->(e) \
                    ) \
                  )",
                params: { 
                  id        : postData.event.ID, 
                  maybeUsed : postData.event.MaybeUsed,
                  fileMD5   : postData.event.filePaths[0],
                  filePaths : postData.event.filePaths[1] 
                }
              }, function (err, results) { 
                if (err) { console.log(err) }else{ console.log('Added MAYBE_USED relationships')} 
              });
            }
            if (postData.event.Created.length != 0) {
              graphDB.cypher({
                query: "MATCH (e:event{id:{id}}),(r:resource) \
                  WHERE r.md5 IN {created} \
                  FOREACH(idx in RANGE(0,SIZE({fileMD5})-1) | \
                    FOREACH( filePath IN CASE WHEN r.md5 = {fileMD5}[idx] THEN [{filePaths}[idx]] ELSE [] END | \
                      CREATE UNIQUE (e)-[:CREATED {filePath:filePath}]->(r) \
                    ) \
                  )",
                params: {
                  id        : postData.event.ID,
                  created   : postData.event.Created,
                  fileMD5   : postData.event.filePaths[0],
                  filePaths : postData.event.filePaths[1]
                }
              }, function (err, results) { 
                if (err) { console.log(err) }else{ console.log('Added CREATED relationships')} 
              });
            }
            if (postData.event.MaybeCreated.length != 0) {
              graphDB.cypher({
                query: "MATCH (e:event{id:{id}}),(r:resource) \
                  WHERE r.md5 IN {maybeCreated} \
                  FOREACH(idx in RANGE(0,SIZE({fileMD5})-1) | \
                    FOREACH( filePath IN CASE WHEN r.md5 = {fileMD5}[idx] THEN [{filePaths}[idx]] ELSE [] END | \
                      CREATE UNIQUE (e)-[:MAYBE_CREATED {filePath:filePath}]->(r) \
                    ) \
                  )",
                params: {
                  id           : postData.event.ID,
                  maybeCreated : postData.event.MaybeCreated,
                  fileMD5      : postData.event.filePaths[0],
                  filePaths    : postData.event.filePaths[1]
                }
              }, function (err, results) { 
                if (err) { console.log(err) }else{ console.log('Added MAYBE_CREATED relationships')} 
              });
            }
            if (postData.event.Deleted.length != 0) {
              graphDB.cypher({
                query: "MATCH (e:event{id:{id}}),(r:resource) \
                  WHERE r.md5 IN {deleted} \
                  FOREACH(idx in RANGE(0,SIZE({fileMD5})-1) | \
                    FOREACH( filePath IN CASE WHEN r.md5 = {fileMD5}[idx] THEN [{filePaths}[idx]] ELSE [] END | \
                      CREATE UNIQUE (e)-[:DELETED {filePath:filePath}]->(r) \
                    ) \
                  )",
                params: { 
                  id        : postData.event.ID,
                  deleted   : postData.event.Deleted,
                  fileMD5   : postData.event.filePaths[0],
                  filePaths : postData.event.filePaths[1]
                }
              }, function (err, results) { 
                if (err) { console.log(err) }else{ console.log('Added DELETED relationships')} 
              });
            }
            if (postData.event.MaybeDeleted.length != 0) {
              graphDB.cypher({
                query: "MATCH (e:event{id:{id}}),(r:resource) \
                  WHERE r.md5 IN {maybeDeleted} \
                  FOREACH(idx in RANGE(0,SIZE({fileMD5})-1) | \
                    FOREACH( filePath IN CASE WHEN r.md5 = {fileMD5}[idx] THEN [{filePaths}[idx]] ELSE [] END | \
                      CREATE UNIQUE (e)-[:MAYBE_DELETED {filePath:filePath}]->(r) \
                    ) \
                  )",
                params: { 
                  id           : postData.event.ID, 
                  maybeDeleted : postData.event.MaybeDeleted,
                  fileMD5      : postData.event.filePaths[0],
                  filePaths    : postData.event.filePaths[1]
                }
              }, function (err, results) { 
                if (err) { console.log(err) }else{ console.log('Added MAYBE_DELETED relationships')} 
              });
            }
            for (var i=0; i(from) \
                    ) \
                  ) \
                  FOREACH(idx in RANGE(0,SIZE({fileMD5})-1) | \
                    FOREACH( filePath IN CASE WHEN to.md5 = {fileMD5}[idx] THEN [{filePaths}[idx]] ELSE [] END | \
                      CREATE UNIQUE (e)-[:CREATED {filePath:filePath}]->(to) \
                    ) \
                  ) \
                  MERGE (from)-[rel:MODIFIED_TO]->(to) \
                  ON CREATE SET rel.by = {id} \
                  ON MATCH SET rel.by = rel.by + {id}",
                params: { 
                  id        : postData.event.ID,
                  from      : postData.event.ModifiedFrom[i],
                  to        : postData.event.ModifiedTo[i],
                  fileMD5   : postData.event.filePaths[0],
                  filePaths : postData.event.filePaths[1]
                }
              }, function (err, results) { 
                if (err) { console.log(err) }else{ console.log('Added MODIFIED ' + i)} 
              });
            }
            for (var i=0; i(from) \
                      ) \
                    ) \
                    FOREACH(idx in RANGE(0,SIZE({fileMD5})-1) | \
                      FOREACH( filePath IN CASE WHEN to.md5 = {fileMD5}[idx] THEN [{filePaths}[idx]] ELSE [] END | \
                        CREATE UNIQUE (e)-[:MAYBE_CREATED {filePath:filePath}]->(to) \
                      ) \
                    ) \
                    MERGE (from)-[rel:MAYBE_MODIFIED_TO]->(to) \
                    ON CREATE SET rel.by = {id} \
                    ON MATCH SET rel.by = rel.by + {id}",
                params: { 
                  id        : postData.event.ID,
                  from      : postData.event.MaybeModifiedFrom[i],
                  to        : postData.event.MaybeModifiedTo[i],
                  fileMD5   : postData.event.filePaths[0],
                  filePaths : postData.event.filePaths[1]
                }
              }, function (err, results) { 
                if (err) { console.log(err) }else{ console.log('Added MAYBE_MODIFIED '+ i)} 
              });
            }
            res.json({success:true});
          });
        } else { res.json({success:false, reason:'Account name or apikey wrong'}); }
      });
    } else { res.json({success:false, reason:'UNACCEPTABLEEEE'}); }
  });
});

// Need to also build in a way to prevent bruteforcing (the server as a whole)
restapi.post('/login', function(req, res){
  parseJSON(req,res,function(postData) {
    if (!('password' in postData)) { postData.password = 'd41d8cd98f00b204e9800998ecf8427e'; } // this is the hash of nothing
    if ('account' in postData) {
      loginPass(postData.account,postData.password,res, function(result) {
        if (result == null) { res.json({account:false,password:null}); }
        else if (result == false) {
          if (postData.password == 'd41d8cd98f00b204e9800998ecf8427e' ){ res.json({account:true,password:null}); }
          else { res.json({  account:true,password:false }); }
        } else {
          res.json({
            account:true,
            password:true,
            data: { account:result.account,
              password:postData.password,
              config:result.config,
              apikey:result.apikey
            }
          }); 
        }
      });
    } else {
      res.json({success:false,reason:'UNACCEPTABLEEEE'});
    }
  });
});     

// takes account, password hash, email address, and captcha data, and creates a new logio account.
restapi.post('/register', function(req, res){
  parseJSON(req,res,function(postData) {
    yoSentinel('register',res);
    if ('account' in postData && 'password' in postData && 'email' in postData && 'submit' in postData) {
    var promises = [];

    promises.push(new Promise( function(resolve, reject) {
      if (postData.account == '') { resolve(null) } else {
        db.get('SELECT COUNT(1) FROM users WHERE account=?;', [postData.account], function(err,row){
          if(!err) {
            if (row['COUNT(1)'] == 0) { resolve(true); } else { resolve(false); }
          } else { reject(err); }
        });
      }
    }));

    promises.push(new Promise( function(resolve, reject) {
      if (postData.email == '') { resolve(null) } else {
        db.get('SELECT COUNT(1) FROM users WHERE email=?;', [postData.email], function(err,row){
          if(!err) {
            if (row['COUNT(1)'] == 0) { resolve(true); } else { resolve(false); }
          } else { reject(err); }
        });
      }
    }));

    promises.push(new Promise( function(resolve, reject) {
      if (postData.captcha === '') { resolve(null); } 
      else {
        var captchaData = {
          secret: '6LcRHwoTAAAAAEgcbOaXk0ITne7W2obWEA3Utt7I',
          response: postData.captcha
        };

        request.post(
          'https://www.google.com/recaptcha/api/siteverify',
          { form: captchaData },
          function (error, response, body) {
            if (!error && response.statusCode == 200) {
              googleSays = JSON.parse(body);
              resolve(googleSays.success);
            } else {
              reject(error);
            }
          }
        );
      }
    }));

    Promise.all(promises).then(function(results) {
      if (postData.password == 'd41d8cd98f00b204e9800998ecf8427e') { var password = null } else {
        if (postData.password.length != 32) { var password = false; } else { var password = true; }
      }
      if (postData.submit != true || results[0] != true || results[1] != true || results[2] != true || password != true) {
        res.json({success:false,account:results[0],email:results[1],captcha:results[2],password:password});
      } else {
        yoSentinel('newRegister',res);
        var apikey = crypto.createHash('md5').update(Math.random().toString(36)).digest('hex');
	var config = JSON.stringify({ apikey: postData.account + ':' + apikey });
        var salt = Math.random().toString(36).replace(/[^a-z]+/g, '');
        var hash = crypto.createHash('md5').update(postData.password + salt).digest('hex');
        var stmt = db.prepare("INSERT INTO users VALUES (?,?,?,?,?,0,strftime('%s', 'now'),?)");
        stmt.run(postData.account,postData.email,hash,salt,apikey,config);
        stmt.finalize();
        res.json({success:true,account:true,email:true,password:true,captcha:true});
      }
    });
  } else {
      res.json({success:false,message:'UNACCEPTABLEEEE'});
    }
  });
});

restapi.post('/getEvents', function(req, res){
  parseJSON(req,res,function(postData) {
    yoSentinel('getEvents',res);

    // The MATCH filters
    var filters = '';
    if ('id' in postData)        { filters = filters + ' id:{id} '               }
    if ('runOn' in postData)     { filters = filters + ' runOn:{runOn} '         }
    if ('runAs' in postData)     { filters = filters + ' runAs:{runAs} '         }
    if ('user' in postData)      { filters = filters + ' user:{user} '           }
    if ('command' in postData)   { filters = filters + ' command:{command} '     }
    if ('account' in postData)   { filters = filters + ' account:{account} '     }
    if ('output' in postData)    { filters = filters + ' output:{output} '       }
    if ('errors' in postData)    { filters = filters + ' errors:{errors} '       }

    // The WHERE filters
    var where = [];
    if ('startTime' in postData) {
      if ('startTimeMin' in postData.startTime) { where.push(" n.startTime > {startTimeMin} "); }
      if ('startTimeMax' in postData.startTime) { where.push(" n.startTime < {startTimeMax} "); }
    } else { postData.startTime = {}; } // required so params doesnt error
    if ('duration' in postData) {
      if ('durationMin' in postData.duration) { where.push(" n.duration > {durationMin} "); }
      if ('durationMax' in postData.duration) { where.push(" n.duration < {durationMax} "); }
    } else { postData.duration = {}; } // required so params doesnt error
    if (where.length == 0) { where = ''}
    else {
      where = 'WHERE (' + where.join(' AND ') + ')';
    }

    // The LIMIT amount.
    if ('limit' in postData && [1,5,10,50,100,500,1000].indexOf(Number(postData.limit)) != -1) { var limit = String(postData.limit);
    } else { var limit = '10'; }

    // Hinge query on a Resource?
    if ('relatedTo' in postData) { var relatedTo = "--(:resource {md5:{relatedTo}}) " } else { var relatedTo = " "; }

    /* 
	It might seem odd that we have 2 database queries here when a "MATCH (n) OPTIONAL MATCH (e)-[rel]-(r) RETURN e,rel,r"
        would do, but the reason is that if we used the single-query method we would get back all the data in the event node 
        (which can be a lot if theres a lot of output) for EVERY relationship. This is kind of scary. A command like 'cat ./*'
        would create a single event with a lot of output, and a lot of relationships, and this duplication of data would be 
        killer if we have to send it down the pipe to the user's browser. So, we've done it as two queries to keep the 
        duplication down. I'm hoping to convince Neo4j to introduce a 'just print node id if full node data already printed' 
        collation function to the return statement, but we will seeeee...
    */

    var query1 = "MATCH (n:event {" + filters + "})" + relatedTo + where + " RETURN n LIMIT "+limit;
    graphDB.cypher({
      query: query1,
      params: {
        id           : postData.id,
        runOn        : postData.runOn,
        runAs        : postData.runAs,
        user         : postData.user,
        command      : postData.command,
        account      : postData.account,
        output       : postData.output,
        errors       : postData.errors,
        startTimeMin : postData.startTime.startTimeMin,
        startTimeMax : postData.startTime.startTimeMax,
        durationMin  : postData.duration.durationMin,
        durationMax  : postData.duration.durationMax,
        relatedTo    : postData.relatedTo
      }
    }, function (err, result1) {
      if (err) { console.log(err,query1); };
      var ids = [];
      for (var i = 0; i < result1.length; i++) { ids.push(result1[i].n.properties.id); }
      var query2 = "\
        MATCH (n:event)-[l]-(r) \
        WHERE n.id IN {ids} \
        RETURN n.id,type(l),l,r";
      graphDB.cypher({
        query: query2,
        params: { ids : ids }
      }, function (err, result2) {
        if (err) { console.log(err,query2); };
        res.json([result1,result2,[query1,query2]]);
      });
    });
  });
});


restapi.post('/getResources', function(req, res){
  parseJSON(req,res,function(postData) {
    yoSentinel('getResources',res);

    // The MATCH filters
    var filters = '';
    if ('addedBy' in postData)  { filters = filters + ' addedBy:{addedBy} '   }
    if ('md5' in postData)      { filters = filters + ' md5:{md5} '           }
    if ('pHash' in postData)    { filters = filters + ' pHash:{pHash} '       }

    // The WHERE filters
    var where = [];
    if ('names' in postData) { where.push(" {names} IN n.names "); }
    if ('filesize' in postData) {
      if ('filesizeMin' in postData.filesize) { where.push(" n.filesize > {filesizeMin} "); }
      if ('filesizeMax' in postData.filesize) { where.push(" n.filesize < {filesizeMax} "); }
    } else { postData.filesize = {}; } // required so params doesnt error

    if (where.length == 0) { where = ''}
    else {
      where = 'WHERE (' + where.join(' AND ') + ')';
    }

    // The LIMIT amount.
    if ('limit' in postData && [1,5,10,50,100,500,1000].indexOf(Number(postData.limit)) != -1) { var limit = String(postData.limit);
    } else { var limit = '10'; }

    // Hinge query on an Event?
    if ('relatedTo' in postData) { var relatedTo = "--(:event {id:{relatedTo}}) " } else { var relatedTo = " "; }

    /* 
	Read the blurb in getEvents if you are curious as to why we do two queries and not just one.
    */

    var query1 = "MATCH (n:resource {" + filters + "})" + relatedTo + where + " RETURN n LIMIT "+limit;
    graphDB.cypher({
      query: query1,
      params: {
        md5          : postData.md5,
        addedBy      : postData.addedBy,
        pHash        : postData.pHash,
        names        : postData.names,
        filesizeMin  : postData.filesize.filesizeMin,
        filesizeMax  : postData.filesize.filesizeMax,
        relatedTo    : postData.relatedTo
      }
    }, function (err, result1) {
      if (err) { console.log(err,query1); };
      var md5s = [];
      for (var i = 0; i < result1.length; i++) { md5s.push(result1[i].n.properties.md5); }
      var query2 = "\
        MATCH (n:resource)-[l]-(e) \
        WHERE n.md5 IN {md5s} \
        RETURN n.md5,type(l),l,e LIMIT 100 ";

      graphDB.cypher({
        query: query2,
        params: { md5s  : md5s }
      }, function (err, result2) {
        if (err) { console.log(err,query2); };
        res.json([result1,result2,[query1,query2]]);
      });
    });
  });
});




restapi.use("/", express.static(rootDir, { maxAge:1, expires:1 })); // 1ms means user never caches page.
restapi.use(compress());
restapi.listen(webPort);
