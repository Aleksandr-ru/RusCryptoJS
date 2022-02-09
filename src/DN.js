function DN(){}

DN.prototype.toString = function () {
	let ret = '';
	for (let i in this) {
        if (this.hasOwnProperty(i)) {
            ret += i + '="' + this[i].replace(/"/g, '\'') + '", ';
        }
    }
	return ret;
};

export default DN;
