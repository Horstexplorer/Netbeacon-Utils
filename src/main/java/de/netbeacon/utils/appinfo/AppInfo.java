/*
 *     Copyright 2020 Horstexplorer @ https://www.netbeacon.de
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

package de.netbeacon.utils.appinfo;

import java.util.Properties;

public class AppInfo {

    private final static Properties properties = new Properties();

    static {
        try{
            properties.load(AppInfo.class.getClassLoader().getResourceAsStream("app.properties"));
        }catch (Exception e){
            e.printStackTrace();
        }
    }

    public static String get(String property){
        String prop = properties.getProperty(property);
        return (prop != null)?prop:"";
    }
}