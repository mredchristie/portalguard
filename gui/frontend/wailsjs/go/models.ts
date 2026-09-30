export namespace main {
	
	export class Network {
	    ssid: string;
	    rssi: number;
	    open: boolean;
	    current: boolean;
	
	    static createFrom(source: any = {}) {
	        return new Network(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.ssid = source["ssid"];
	        this.rssi = source["rssi"];
	        this.open = source["open"];
	        this.current = source["current"];
	    }
	}
	export class Scan {
	    location: string;
	    power: boolean;
	    current: string;
	    networks: Network[];
	    hidden: number;
	    error?: string;
	
	    static createFrom(source: any = {}) {
	        return new Scan(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.location = source["location"];
	        this.power = source["power"];
	        this.current = source["current"];
	        this.networks = this.convertValues(source["networks"], Network);
	        this.hidden = source["hidden"];
	        this.error = source["error"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}

}

