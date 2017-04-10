import * as JwtAuth from "jsonwebtoken";
import * as File from "fs";
import { Kanro } from "kanro";

declare module "kanro" {
    namespace Kanro {
        namespace Http {
            interface IRequest {
                auth?: { [name: string]: any };
            }
        }
    }
}

export namespace Jwt {
    export namespace Exceptions {
        export class JwtNoSecretException extends Kanro.Exceptions.KanroException {
            name = "Kanro.Jwt.NoSecret";

            constructor(message: string = "No jwt secret or cert provided.", innerException: Error = undefined) {
                super(message);
                this.message = message;
                this.innerException = innerException;
            }
        }
    }

    export class JwtAuthenticator extends Kanro.Executors.BaseRequestHandler {
        async handler(request: Kanro.Http.IRequest): Promise<Kanro.Http.IRequest> {
            let token = request.header["authorization"];
            if (token == undefined || !token.startsWith("Bearer ")) {
                throw new Kanro.Exceptions.KanroUnauthorizedException();
            }

            let kanroManager = <Kanro.Core.IKanroManager>this.dependencies["KanroManager"];

            if (this.jwtCert == undefined) {
                this.jwtCert = kanroManager.getKanroConfig("jwtCert");
                if (this.jwtCert != undefined) {
                    await new Promise((res, rej) => {
                        File.readFile(this.jwtCert, (err, data) => {
                            if (err) {
                                rej(err);
                                return;
                            }
                            this.jwtSecret = data;
                            res();
                        });
                    });
                    this.jwtCert = undefined;
                }
            }
            if (this.jwtSecret == undefined) {
                this.jwtSecret = kanroManager.getKanroConfig("jwtSecret");
            }
            if (this.jwtVerifyOptions == undefined) {
                this.jwtVerifyOptions = kanroManager.getKanroConfig("jwtVerifyOptions");
            }

            if (this.jwtSecret == undefined) {
                throw new Exceptions.JwtNoSecretException();
            }

            try {
                new Promise((res, rej) => {
                    JwtAuth.verify(token.slice(7), this.jwtSecret, this.jwtVerifyOptions, (err, decoded) => {
                        if (err) {
                            rej(err);
                            return;
                        }
                        request.auth = decoded;
                        res();
                    });
                })
            }
            catch (err) {
                throw new Kanro.Exceptions.KanroUnauthorizedException("Jwt authorization fail.", err);
            }

            return request;
        }

        type: Kanro.Executors.ExecutorType.RequestHandler = Kanro.Executors.ExecutorType.RequestHandler;
        name: string = "JwtAuthenticator";
        jwtSecret: string | Buffer;
        jwtCert: string;
        jwtVerifyOptions: JwtAuth.VerifyOptions;

        constructor(config: Kanro.Containers.IRequestHandlerContainer) {
            super(config);
            this.dependencies = { KanroManager: { name: "Kanro.Core", version: "" } };

            if (config["jwtSecret"] != undefined) {
                this.jwtSecret = config["jwtSecret"];
            }
            if (config["jwtCert"] != undefined) {
                this.jwtCert = config["jwtCert"];
            }
            if (config["jwtVerifyOptions"] != undefined) {
                this.jwtVerifyOptions = config["jwtVerifyOptions"];
            }
        }
    }

    export class JwtSigner implements Kanro.Executors.IService {
        dependencies: { [name: string]: Kanro.Executors.IService | Kanro.Core.IModuleInfo; };
        type: Kanro.Executors.ExecutorType.Service = Kanro.Executors.ExecutorType.Service;
        name: string = "JwtSigner";
        jwtSecret: string | Buffer;
        jwtCert: string;
        jwtSignOptions: JwtAuth.SignOptions;

        async sign(payload: any, jwtSecret: string | Buffer = undefined, jwtSignOptions: JwtAuth.SignOptions = undefined): Promise<string> {
            let kanroManager = <Kanro.Core.IKanroManager>this.dependencies["KanroManager"];
            if (jwtSecret == undefined) {
                if (this.jwtCert == undefined) {
                    this.jwtCert = kanroManager.getKanroConfig("jwtCert");
                    if (this.jwtCert != undefined) {
                        await new Promise((res, rej) => {
                            File.readFile(this.jwtCert, (err, data) => {
                                if (err) {
                                    rej(err);
                                    return;
                                }
                                this.jwtSecret = data;
                                res();
                            });
                        });
                        this.jwtCert = undefined;
                    }
                }
                if (this.jwtSecret == undefined) {
                    this.jwtSecret = kanroManager.getKanroConfig("jwtSecret");
                }
                jwtSecret = this.jwtSecret;
            }
            if (jwtSignOptions == undefined) {
                if (this.jwtSignOptions == undefined) {
                    this.jwtSignOptions = kanroManager.getKanroConfig("jwtSignOptions");
                }
                jwtSignOptions = this.jwtSignOptions;
            }
            if (jwtSecret == undefined) {
                throw new Exceptions.JwtNoSecretException();
            }

            return await new Promise<string>((res, rej) => {
                JwtAuth.sign(payload, jwtSecret, jwtSignOptions, (err, encoded) => {
                    if (err) {
                        rej(err);
                        return;
                    }
                    res(encoded);
                });
            });
        }

        constructor(config: Kanro.Containers.IServiceContainer) {
            this.dependencies = { KanroManager: { name: "Kanro", version: "*" } };

            if (config["jwtSecret"] != undefined) {
                this.jwtSecret = config["jwtSecret"];
            }
            if (config["jwtCert"] != undefined) {
                this.jwtCert = config["jwtCert"];
            }
            if (config["jwtSignOptions"] != undefined) {
                this.jwtSignOptions = config["jwtSignOptions"];
            }
        }
    }

    export class JwtModule implements Kanro.Core.IModule {
        dependencies: Kanro.Core.IModuleInfo[];

        executorInfos: { [name: string]: Kanro.Executors.IExecutorInfo; };
        async getExecutor(config: Kanro.Containers.IExecutorContainer): Promise<Kanro.Executors.IExecutor> {
            switch (config.name) {
                case "JwtAuthenticator":
                    return new JwtAuthenticator(<any>config);
                case "JwtSigner":
                    return new JwtSigner(<any>config);
                default:
                    return undefined;
            }
        }

        public constructor() {
            this.executorInfos = {
                JwtAuthenticator: { type: Kanro.Executors.ExecutorType.RequestHandler, name: "JwtAuthenticator" },
                JwtSigner: { type: Kanro.Executors.ExecutorType.Service, name: "JwtSigner" }
            };
        }
    }
}

export let KanroModule = new Jwt.JwtModule(); 