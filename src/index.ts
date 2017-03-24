import * as JwtAuth from "jsonwebtoken";
import * as File from "fs";
import { Kanro } from "kanro.core";

declare module "kanro.core" {
    namespace Kanro {
        namespace Core {
            interface IRequest {
                auth: { [name: string]: any };
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

    export class JwtAuthenticator extends Kanro.BaseRequestHandler {
        async handler(request: Kanro.Core.IRequest): Promise<Kanro.Core.IRequest> {
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

        type: Kanro.Core.ExecutorType.RequestHandler = Kanro.Core.ExecutorType.RequestHandler;
        name: string = "JwtAuthenticator";
        jwtSecret: string | Buffer;
        jwtCert: string;
        jwtVerifyOptions: JwtAuth.VerifyOptions;

        constructor(config: Kanro.Config.IRequestHandlerConfig) {
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

    export class JwtSigner implements Kanro.Core.IService {
        dependencies: { [name: string]: Kanro.Core.IService | Kanro.Core.IModuleInfo; };
        type: Kanro.Core.ExecutorType.Service = Kanro.Core.ExecutorType.Service;
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

        constructor(config: Kanro.Config.IServiceConfig) {
            this.dependencies = { KanroManager: { name: "Kanro.Core", version: "*" } };

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

        executorInfos: { [name: string]: Kanro.Core.IExecutorInfo; };
        async getExecutor(config: Kanro.Config.IExecutorConfig): Promise<Kanro.Core.IExecutor> {
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
                JwtAuthenticator: { type: Kanro.Core.ExecutorType.RequestHandler, name: "JwtAuthenticator" },
                JwtSigner: { type: Kanro.Core.ExecutorType.Service, name: "JwtSigner" }
            };
        }
    }
}

export let KanroModule = new Jwt.JwtModule(); 