import {Observable} from "rxjs";
import {AuthDriverManifests} from "../../model/authentication.model";
import {Injectable} from "@angular/core";
import {HttpClient} from "@angular/common/http";

/**
 * Service to get downloads
 */
@Injectable()
export class DriversService {

    constructor(private _http: HttpClient) {
    }

    getDrivers(): Observable<Array<string>> {
        return this._http.get<Array<string>>('/drivers');
    }
}

