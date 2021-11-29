function DN(){};

DN.prototype.toString = function(){
	var ret = '';
	for(var i in this) {
        if(this.hasOwnProperty(i)) {
            ret += i + '="' + this[i].replace(/"/g, '\'') + '", ';
        }
    }
	return ret;
};

export default DN;
