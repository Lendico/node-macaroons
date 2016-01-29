function shallowFlatten(list) { return [].concat.apply([], list); }
exports.shallowFlatten = shallowFlatten;

function deepFlatten (maybeList){ 
  return Array.isArray(maybeList) ? shallowFlatten(maybeList.map(deepFlatten)) : maybeList; 
}
exports.deepFlatten = deepFlatten;

exports.asyncMap = function(list, itFun, resFn) {
  var revList = list.reverse();
  var resultList = [];

  function runAsyncIteration(err, result) {
    resultList.push(result);
    return (err || !revList.length) ? resFn(err, resultList) : itFun(revList.pop(), runAsyncIteration);
  }

  return !revList.length ? resFn(null, resultList) : itFun(revList.pop(), runAsyncIteration);
}