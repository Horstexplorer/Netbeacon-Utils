/*
 *     Copyright 2021 Horstexplorer @ https://www.netbeacon.de
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *          http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package de.netbeacon.utils.statistics;

import java.util.ArrayList;
import java.util.List;

public class LimitedCache<O> {

    private final int maxSite;
    private final List<O> data = new ArrayList<>();

    public LimitedCache(int maxSize){
        this.maxSite = maxSize;
    }

    public int getMaxSize() {
        return maxSite;
    }

    public synchronized void add(O object){
        data.add(object);
        if(data.size() > maxSite){
            data.remove(0);
        }
    }

    public List<O> getAll(){
        return new ArrayList<>(data);
    }
}
