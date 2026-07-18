// Consuming source so `ci` reachability marks lodash as Used (not downgraded).
const _ = require('lodash');
const merged = _.merge({}, { a: 1 });
console.log(_.template('<%= x %>')({ x: 1 }), merged);
